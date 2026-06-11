package gdpr

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/gmb-sig/go-platform-kit/broker"
	"github.com/gmb-sig/go-platform-kit/observability"
)

// Errors returned by the client.
var (
	// ErrNotConfigured is returned when the client has no Poster.
	ErrNotConfigured = errors.New("gdpr-audit: client has no poster")
	// ErrMissingLawfulBasis is returned when an access record carries no lawful
	// basis — GDPR accountability requires one on every access.
	ErrMissingLawfulBasis = errors.New("gdpr-audit: access record missing lawful_basis")
)

// MetricRecordsTotal counts access records by delivery outcome.
const MetricRecordsTotal = "gdpr_audit_records_total"

// Delivery-outcome metric label values.
const (
	outcomePosted       = "posted"        // persisted (sync or drained)
	outcomeBuffered     = "buffered"      // sync post failed or breaker open, queued for retry
	outcomeFailedClosed = "failed_closed" // privileged post failed → caller aborts
	outcomeDropped      = "dropped"       // not persisted and not buffered (dead-lettered when configured)
)

// maxBackoff caps the drainer's exponential backoff.
const maxBackoff = 30 * time.Second

// MaxAttrValueLen is the maximum length (in runes) of a string attribute value.
// Longer values are truncated by sanitize — bounded operational metadata
// (e.g. AttrReason, AttrWhat, AttrRecipient) is permitted, unbounded free text
// is not (see the PII posture in the package documentation).
const MaxAttrValueLen = 256

// DeadLetterFunc receives a record that the client is about to drop (outbox
// full, drain retries exhausted, or flush failure) so the service can persist
// it out-of-band (e.g. to local disk or an ops queue) instead of losing it.
// It must not block for long and must not panic.
type DeadLetterFunc func(rec *broker.Envelope)

// Client records Regime B personal-data access. Construct one per service with
// New, run Drain in a background goroutine for buffered-record delivery, and
// call Close on shutdown (it stops the drainer and flushes the outbox in the
// right order). It is safe for concurrent use.
type Client struct {
	cfg        Configuration
	poster     Poster
	outbox     Outbox
	log        *zap.Logger
	deadLetter DeadLetterFunc

	// circuit-breaker state (guards request latency against a slow/failing sink)
	brMu      sync.Mutex
	fails     int
	openUntil time.Time

	// drain lifecycle (owned by Drain / Close)
	lcMu      sync.Mutex
	draining  bool
	drainStop context.CancelFunc
	drainDone chan struct{}
}

// Options carries optional dependencies for New.
type Options struct {
	// Outbox overrides the default in-memory fallback buffer. The default
	// MemoryOutbox is per-pod and NON-DURABLE — buffered records are lost on a
	// crash/redeploy. Production services should supply a durable implementation
	// (the shipped FileOutbox, or a DB-backed one).
	Outbox Outbox
	// DeadLetter, when set, receives every record the client would otherwise
	// drop (outbox full, drain retries exhausted, flush failure) so it can be
	// persisted out-of-band. Strongly recommended together with a MemoryOutbox.
	DeadLetter DeadLetterFunc
	// Logger is used for drop/lifecycle warnings. Defaults to a no-op logger.
	Logger *zap.Logger
}

// New constructs a Client posting through poster. It does not start any
// goroutine; the service runs Drain to deliver buffered records and calls
// Close on shutdown.
func New(cfg Configuration, poster Poster, opts ...Options) (*Client, error) {
	if poster == nil {
		return nil, ErrNotConfigured
	}

	cfg.setDefaults()

	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	log := opt.Logger
	if log == nil {
		log = zap.NewNop()
	}

	outbox := opt.Outbox
	if outbox == nil {
		outbox = NewMemoryOutbox(cfg.OutboxCapacity)
		log.Warn("gdpr-audit: using the default in-memory outbox — buffered access records will NOT survive a crash/redeploy; supply a durable Outbox (e.g. FileOutbox) or a DeadLetter sink for production")
	}

	return &Client{cfg: cfg, poster: poster, outbox: outbox, log: log, deadLetter: opt.DeadLetter}, nil
}

// Access is the general personal-data-access parameter set. Use it with Record /
// RecordPrivileged for events without a dedicated helper.
type Access struct {
	// Actor is the acting identity, or a service identity for automated access.
	Actor broker.Actor
	// DataSubjects are the people the access concerns — drives subject indexing.
	// Values MUST be pseudonymous internal identity references (e.g. the
	// identity-record ULID) — NEVER national identifiers, personal codes, names,
	// or e-mail addresses.
	DataSubjects []string
	// Resource is what was touched (document/envelope/identity).
	Resource broker.Resource
	// Operation is read | create | update | delete | export.
	Operation broker.Operation
	// LawfulBasis is the GDPR Art. 6 basis (required). See Basis* constants.
	LawfulBasis string
	// Purpose explains why the data was processed. See Purpose* constants.
	Purpose string
	// Channel is interactive | background.
	Channel string
	// Attributes are extra identifiers and bounded operational metadata — never
	// document content or unbounded free text (string values are length-capped
	// at MaxAttrValueLen; content-bearing keys are stripped).
	Attributes map[string]any
}

// Record posts a routine personal-data-access record. On a transient
// access-audit failure (or while the circuit breaker is open) the record is
// buffered to the Outbox for background retry and Record returns nil (graceful
// degradation); it returns an error only when the record is invalid or the
// buffer is full.
//
// Back-pressure contract: callers MUST treat a non-nil error from a routine
// Record as non-fatal for the user operation (log + continue) — the
// progression on a sustained sink outage is sync → buffered → buffer-full →
// error, and failing user reads on audit back-pressure inverts the graceful-
// degradation design. Alert on the `dropped` outcome of MetricRecordsTotal
// instead.
func (c *Client) Record(ctx *azugo.Context, eventType string, a Access) error {
	return c.record(ctx, build(eventType, a), false)
}

// RecordPrivileged posts an elevated personal-data-access record fail-closed: if
// it cannot be persisted, RecordPrivileged returns an error so the caller can
// abort the operation. Use it for operator/break-glass access, exports, erasure
// and DSAR fulfilment — accountability is not optional for these. Privileged
// records always attempt the synchronous post, even while the circuit breaker
// is open.
func (c *Client) RecordPrivileged(ctx *azugo.Context, eventType string, a Access) error {
	return c.record(ctx, build(eventType, a), true)
}

// record stamps, validates and delivers an access record, applying the
// fail-closed (critical) or buffered (routine) policy on a delivery failure.
func (c *Client) record(ctx *azugo.Context, ev *broker.Envelope, critical bool) error {
	if c == nil || c.poster == nil {
		return ErrNotConfigured
	}

	ev.Categories = []broker.Category{broker.CategoryGDPRAccess}
	ev.Attributes = sanitize(ev.Attributes)

	broker.Stamp(ctx, ev)

	if ev.LawfulBasis == "" {
		return ErrMissingLawfulBasis
	}

	if err := ev.Validate(); err != nil {
		return err
	}

	// Breaker open: skip the synchronous attempt to protect interactive
	// latency; buffer immediately. Privileged records always attempt.
	if !critical && c.breakerOpen() {
		return c.buffer(ev, nil)
	}

	err := c.post(ctx, ev)
	if err == nil {
		incRecord(outcomePosted)

		return nil
	}

	if critical {
		incRecord(outcomeFailedClosed)

		return fmt.Errorf("gdpr-audit: fail-closed access record not persisted: %w", err)
	}

	return c.buffer(ev, err)
}

// buffer enqueues a routine record for background delivery; on a full outbox it
// dead-letters the record and returns an error the caller must treat as
// non-fatal (see Record).
func (c *Client) buffer(ev *broker.Envelope, cause error) error {
	if encErr := c.outbox.Enqueue(ev); encErr != nil {
		c.drop(ev, "outbox full", cause)

		if cause != nil {
			return fmt.Errorf("gdpr-audit: access record not persisted and outbox full: %w", errors.Join(cause, encErr))
		}

		return fmt.Errorf("gdpr-audit: access record not persisted and outbox full: %w", encErr)
	}

	incRecord(outcomeBuffered)

	return nil
}

// post delivers one record through the Poster, bounded by cfg.Timeout (the
// timeout is enforced here, not advisory), and feeds the circuit breaker.
//
// The parent context is detached via context.WithoutCancel before the timeout
// is derived. Two reasons: (1) deriving a cancel-context directly from a
// pooled fasthttp/azugo request context spawns a stdlib watcher goroutine that
// can outlive the request and read the context after azugo has reset and
// reused it — a data race (caught by -race); (2) an audit post, once started,
// should complete or hit its own timeout rather than be torn down by request
// cancellation — losing the record because the user disconnected is the wrong
// outcome for an accountability log. Context values remain available to the
// Poster; the post is always bounded by cfg.Timeout.
func (c *Client) post(ctx context.Context, rec *broker.Envelope) error {
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.cfg.Timeout)
	defer cancel()

	err := c.poster.Post(pctx, rec)
	c.observe(err)

	return err
}

// observe updates the circuit-breaker state from a post outcome.
func (c *Client) observe(err error) {
	if c.cfg.BreakerThreshold <= 0 {
		return
	}

	c.brMu.Lock()
	defer c.brMu.Unlock()

	if err == nil {
		c.fails = 0
		c.openUntil = time.Time{}

		return
	}

	c.fails++
	if c.fails >= c.cfg.BreakerThreshold {
		c.openUntil = time.Now().Add(c.cfg.BreakerCooldown)
	}
}

// breakerOpen reports whether the breaker currently short-circuits routine
// synchronous posts. After the cooldown elapses the next call attempts again
// (half-open); a further failure re-opens the breaker.
func (c *Client) breakerOpen() bool {
	if c.cfg.BreakerThreshold <= 0 {
		return false
	}

	c.brMu.Lock()
	defer c.brMu.Unlock()

	return time.Now().Before(c.openUntil)
}

// Drain delivers buffered records until ctx is cancelled. Run it once in a
// background goroutine with an application-lifetime context —
// go client.Drain(appCtx) — never a per-request (pooled) context; prefer
// stopping it via Close, which also flushes. Each record is retried with jittered exponential backoff
// up to MaxRetries; a record that still cannot be delivered is dead-lettered
// (when a DeadLetter sink is configured) and dropped with a warning. A second
// concurrent Drain call is ignored.
func (c *Client) Drain(ctx context.Context) {
	c.lcMu.Lock()
	if c.draining {
		c.lcMu.Unlock()
		c.log.Warn("gdpr-audit: Drain already running; ignoring duplicate call")

		return
	}

	dctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	c.draining = true
	c.drainStop = cancel
	c.drainDone = done
	c.lcMu.Unlock()

	defer func() {
		cancel()

		c.lcMu.Lock()
		c.draining = false
		c.drainStop = nil
		c.drainDone = nil
		c.lcMu.Unlock()

		close(done)
	}()

	for {
		rec, err := c.outbox.Dequeue(dctx)
		if err != nil {
			return
		}

		c.deliver(dctx, rec)
	}
}

// deliver retries a single buffered record with capped, jittered exponential
// backoff. If ctx is cancelled mid-retry the record is re-buffered so a
// subsequent Flush/Close can still deliver it.
func (c *Client) deliver(ctx context.Context, rec *broker.Envelope) {
	backoff := c.cfg.RetryBackoff

	for attempt := 0; ; attempt++ {
		if err := c.post(ctx, rec); err == nil {
			incRecord(outcomePosted)

			return
		}

		if attempt >= c.cfg.MaxRetries {
			c.drop(rec, "drain retries exhausted", nil)

			return
		}

		select {
		case <-ctx.Done():
			if err := c.outbox.Enqueue(rec); err != nil {
				c.drop(rec, "drain cancelled and outbox full", err)
			}

			return
		case <-time.After(jitter(backoff)):
		}

		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

// jitter spreads a backoff delay over [d/2, d] so recovering sinks are not hit
// by a thundering herd of synchronized retries.
func jitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}

	half := d / 2

	return half + rand.N(half+1)
}

// Flush synchronously delivers every currently-buffered record, best-effort,
// for graceful shutdown. Prefer Close, which stops the drainer first so the
// two do not both consume the Outbox.
func (c *Client) Flush(ctx context.Context) error {
	for c.outbox.Len() > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		rec, err := c.outbox.Dequeue(ctx)
		if err != nil {
			return err
		}

		if err := c.post(ctx, rec); err != nil {
			c.drop(rec, "flush failed", err)
		}
	}

	return nil
}

// Close stops the background drainer (if running), waits for it to exit, and
// then flushes the outbox — the single shutdown call that replaces the manual
// "cancel Drain, then Flush" ordering. It is bounded by ctx.
func (c *Client) Close(ctx context.Context) error {
	c.lcMu.Lock()
	stop, done := c.drainStop, c.drainDone
	c.lcMu.Unlock()

	if stop != nil {
		stop()

		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return c.Flush(ctx)
}

// drop counts, logs and (when configured) dead-letters a record that could not
// be persisted or buffered.
func (c *Client) drop(rec *broker.Envelope, reason string, err error) {
	incRecord(outcomeDropped)
	c.log.Warn("gdpr-audit: dropping access record",
		zap.String("reason", reason),
		zap.String("event_id", rec.EventID),
		zap.String("event_type", rec.EventType),
		zap.Error(err),
	)

	if c.deadLetter != nil {
		c.deadLetter(rec)
	}
}

// build assembles a Regime B access envelope from the general parameter set.
func build(eventType string, a Access) *broker.Envelope {
	attrs := make(map[string]any, len(a.Attributes)+1)
	for k, v := range a.Attributes {
		attrs[k] = v
	}

	if a.Channel != "" {
		attrs[AttrChannel] = a.Channel
	}

	return &broker.Envelope{
		EventType:    eventType,
		Categories:   []broker.Category{broker.CategoryGDPRAccess},
		Actor:        actor(a.Actor),
		DataSubjects: a.DataSubjects,
		Resource:     resourceOrNil(a.Resource),
		Operation:    a.Operation,
		LawfulBasis:  a.LawfulBasis,
		Purpose:      a.Purpose,
		Outcome:      broker.OutcomeSuccess,
		Attributes:   compact(attrs),
	}
}

func incRecord(outcome string) {
	observability.IncCounter(MetricRecordsTotal, map[string]string{
		observability.LabelOutcome: outcome,
	})
}

// actor returns a pointer to a copy of a when it carries any identity, else nil.
func actor(a broker.Actor) *broker.Actor {
	if a.ID == "" && a.Type == "" && a.Assurance == "" {
		return nil
	}

	return &a
}

// resourceOrNil returns a pointer to r when it carries anything, else nil.
func resourceOrNil(r broker.Resource) *broker.Resource {
	if r.Type == "" && r.ID == "" {
		return nil
	}

	return &r
}

func subjects(id string) []string {
	if id == "" {
		return nil
	}

	return []string{id}
}

func channelOr(channel, def string) string {
	if channel == "" {
		return def
	}

	return channel
}

func opOr(op, def broker.Operation) broker.Operation {
	if op == "" {
		return def
	}

	return op
}

// forbiddenAttrKeys name attribute payloads that would put document content or
// unbounded free text into the access log. This log is itself PII — only
// identifiers, the operation, the basis, and bounded operational metadata
// belong in it (Audit Design §4).
var forbiddenAttrKeys = []string{
	"document_bytes", "content_bytes", "file_bytes", "content",
	"free_text", "note", "comment", "body", "payload", "message",
	"description", "remarks",
}

// sanitize drops content-bearing attribute keys defensively and truncates any
// string attribute value to MaxAttrValueLen runes, so permitted operational
// metadata (reason/what/recipient) stays bounded. The publisher additionally
// strips bearer-token-shaped keys (broker.Stamp).
func sanitize(attrs map[string]any) map[string]any {
	if len(attrs) == 0 {
		return attrs
	}

	for k := range attrs {
		lk := strings.ToLower(k)
		for _, f := range forbiddenAttrKeys {
			if strings.Contains(lk, f) {
				delete(attrs, k)

				break
			}
		}
	}

	for k, v := range attrs {
		s, ok := v.(string)
		if !ok {
			continue
		}

		if r := []rune(s); len(r) > MaxAttrValueLen {
			attrs[k] = string(r[:MaxAttrValueLen])
		}
	}

	return attrs
}

// compact removes nil and empty-string attribute values; booleans and numbers
// (incl. zero) are kept.
func compact(attrs map[string]any) map[string]any {
	for k, v := range attrs {
		if v == nil {
			delete(attrs, k)

			continue
		}

		if s, ok := v.(string); ok && s == "" {
			delete(attrs, k)
		}
	}

	if len(attrs) == 0 {
		return nil
	}

	return attrs
}
