package gdpr

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	outcomeBuffered     = "buffered"      // sync post failed, queued for retry
	outcomeFailedClosed = "failed_closed" // privileged post failed → caller aborts
	outcomeDropped      = "dropped"       // not persisted and not buffered
)

// maxBackoff caps the drainer's exponential backoff.
const maxBackoff = 30 * time.Second

// Client records Regime B personal-data access. Construct one per service with
// New, run Drain in a background goroutine for buffered-record delivery, and call
// Flush on shutdown. It is safe for concurrent use.
type Client struct {
	cfg    Configuration
	poster Poster
	outbox Outbox
	log    *zap.Logger
}

// Options carries optional dependencies for New.
type Options struct {
	// Outbox overrides the default in-memory fallback buffer (e.g. a durable one).
	Outbox Outbox
	// Logger is used for drop warnings on the background drain path. Defaults to
	// a no-op logger.
	Logger *zap.Logger
}

// New constructs a Client posting through poster. It does not start any
// goroutine; the service runs Drain to deliver buffered records.
func New(cfg Configuration, poster Poster, opts ...Options) (*Client, error) {
	if poster == nil {
		return nil, ErrNotConfigured
	}

	cfg.setDefaults()

	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	outbox := opt.Outbox
	if outbox == nil {
		outbox = NewMemoryOutbox(cfg.OutboxCapacity)
	}

	log := opt.Logger
	if log == nil {
		log = zap.NewNop()
	}

	return &Client{cfg: cfg, poster: poster, outbox: outbox, log: log}, nil
}

// Access is the general personal-data-access parameter set. Use it with Record /
// RecordPrivileged for events without a dedicated helper.
type Access struct {
	// Actor is the acting identity, or a service identity for automated access.
	Actor broker.Actor
	// DataSubjects are the people the access concerns — drives subject indexing.
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
	// Attributes are extra identifiers/metadata — never free-text or content.
	Attributes map[string]any
}

// Record posts a routine personal-data-access record. On a transient
// access-audit failure the record is buffered to the Outbox for background retry
// and Record returns nil (graceful degradation); it returns an error only when
// the record is invalid or the buffer is full.
func (c *Client) Record(ctx *azugo.Context, eventType string, a Access) error {
	return c.record(ctx, build(eventType, a), false)
}

// RecordPrivileged posts an elevated personal-data-access record fail-closed: if
// it cannot be persisted, RecordPrivileged returns an error so the caller can
// abort the operation. Use it for operator/break-glass access, exports, erasure
// and DSAR fulfilment — accountability is not optional for these.
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

	err := c.poster.Post(ctx, ev)
	if err == nil {
		incRecord(outcomePosted)

		return nil
	}

	if critical {
		incRecord(outcomeFailedClosed)

		return fmt.Errorf("gdpr-audit: fail-closed access record not persisted: %w", err)
	}

	if encErr := c.outbox.Enqueue(ev); encErr != nil {
		incRecord(outcomeDropped)

		return fmt.Errorf("gdpr-audit: access record not persisted and outbox full: %w", errors.Join(err, encErr))
	}

	incRecord(outcomeBuffered)

	return nil
}

// Drain delivers buffered records until ctx is cancelled. Run it once in a
// background goroutine: go client.Drain(appCtx). Each record is retried with
// exponential backoff up to MaxRetries; a record that still cannot be delivered
// is dropped with a warning (a durable Outbox avoids this).
func (c *Client) Drain(ctx context.Context) {
	for {
		rec, err := c.outbox.Dequeue(ctx)
		if err != nil {
			return
		}

		c.deliver(ctx, rec)
	}
}

// deliver retries a single buffered record with capped exponential backoff.
func (c *Client) deliver(ctx context.Context, rec *broker.Envelope) {
	backoff := c.cfg.RetryBackoff

	for attempt := 0; ; attempt++ {
		if err := c.poster.Post(ctx, rec); err == nil {
			incRecord(outcomePosted)

			return
		}

		if attempt >= c.cfg.MaxRetries {
			incRecord(outcomeDropped)
			c.log.Warn("gdpr-audit: dropping buffered access record after retries",
				zap.String("event_id", rec.EventID),
				zap.String("event_type", rec.EventType),
			)

			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

// Flush synchronously delivers every currently-buffered record, best-effort, for
// graceful shutdown. Stop Drain (cancel its context) before calling Flush so the
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

		if err := c.poster.Post(ctx, rec); err != nil {
			incRecord(outcomeDropped)
			c.log.Warn("gdpr-audit: dropping buffered access record on flush",
				zap.String("event_id", rec.EventID),
				zap.Error(err),
			)
		}
	}

	return nil
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

// forbiddenAttrKeys name attribute payloads that would put free-text or document
// content into the access log. This log is itself PII — only identifiers, the
// operation, and the basis belong in it (Audit Design §4).
var forbiddenAttrKeys = []string{
	"document_bytes", "content_bytes", "file_bytes", "content",
	"free_text", "note", "comment", "body", "payload", "message",
}

// sanitize drops free-text/content attribute keys defensively. The publisher
// additionally strips bearer-token-shaped keys (broker.Stamp).
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
