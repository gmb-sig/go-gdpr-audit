package gdpr_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"

	"github.com/gmb-sig/go-gdpr-audit/gdpr"
	"github.com/gmb-sig/go-platform-kit/broker"
)

// blockingPoster blocks every Post until its context is cancelled (a hung
// sink), proving the client enforces the per-post timeout.
type blockingPoster struct{}

func (blockingPoster) Post(ctx context.Context, _ *broker.Envelope) error {
	<-ctx.Done()

	return ctx.Err()
}

func routineAccess() gdpr.Access {
	return gdpr.Access{
		DataSubjects: []string{"subject-1"},
		Resource:     broker.Resource{Type: gdpr.ResourceDocument, ID: "doc-1"},
		Operation:    broker.OpRead,
		LawfulBasis:  gdpr.BasisContract,
	}
}

func TestPost_TimeoutBoundsHungPoster(t *testing.T) {
	cfg := testConfig()
	cfg.Timeout = 50 * time.Millisecond

	ob := gdpr.NewMemoryOutbox(16)
	client, err := gdpr.New(cfg, blockingPoster{}, gdpr.Options{Outbox: ob})
	qt.Assert(t, qt.IsNil(err))

	var (
		rerr    error
		elapsed time.Duration
	)

	withCtx(t, func(ctx *azugo.Context) {
		start := time.Now()
		rerr = client.Record(ctx, gdpr.EventDocumentAccess, routineAccess())
		elapsed = time.Since(start)
	})

	// The hung post is cut off by the enforced timeout, the record is buffered,
	// and the caller is not blocked indefinitely.
	qt.Assert(t, qt.IsNil(rerr))
	qt.Check(t, qt.Equals(ob.Len(), 1))
	qt.Check(t, qt.IsTrue(elapsed < 2*time.Second), qt.Commentf("record blocked for %v", elapsed))
}

func TestBreaker_OpensAndBuffersImmediately(t *testing.T) {
	cfg := testConfig()
	cfg.BreakerThreshold = 2
	cfg.BreakerCooldown = time.Minute

	p := &fakePoster{alwaysFail: true}
	ob := gdpr.NewMemoryOutbox(16)
	client, err := gdpr.New(cfg, p, gdpr.Options{Outbox: ob})
	qt.Assert(t, qt.IsNil(err))

	withCtx(t, func(ctx *azugo.Context) {
		// Two failures trip the breaker…
		qt.Check(t, qt.IsNil(client.Record(ctx, gdpr.EventDocumentAccess, routineAccess())))
		qt.Check(t, qt.IsNil(client.Record(ctx, gdpr.EventDocumentAccess, routineAccess())))
		// …so the third routine record must buffer without touching the poster.
		qt.Check(t, qt.IsNil(client.Record(ctx, gdpr.EventDocumentAccess, routineAccess())))
	})

	qt.Check(t, qt.Equals(p.callCount(), 2), qt.Commentf("third record must not hit the open breaker"))
	qt.Check(t, qt.Equals(ob.Len(), 3))
}

func TestBreaker_PrivilegedAlwaysAttempts(t *testing.T) {
	cfg := testConfig()
	cfg.BreakerThreshold = 1
	cfg.BreakerCooldown = time.Minute

	p := &fakePoster{alwaysFail: true}
	client, err := gdpr.New(cfg, p, gdpr.Options{Outbox: gdpr.NewMemoryOutbox(16)})
	qt.Assert(t, qt.IsNil(err))

	withCtx(t, func(ctx *azugo.Context) {
		qt.Check(t, qt.IsNil(client.Record(ctx, gdpr.EventDocumentAccess, routineAccess()))) // trips breaker
		qt.Check(t, qt.IsNotNil(client.RecordPrivileged(ctx, gdpr.EventPrivilegedAccess, routineAccess())))
	})

	// Both the routine trip and the privileged attempt reached the poster.
	qt.Check(t, qt.Equals(p.callCount(), 2))
}

func TestClose_StopsDrainAndFlushes(t *testing.T) {
	// First (synchronous) post fails → buffered; Close must deliver it via Flush.
	p := &fakePoster{failUntil: 1}
	ob := gdpr.NewMemoryOutbox(16)
	client, err := gdpr.New(testConfig(), p, gdpr.Options{Outbox: ob})
	qt.Assert(t, qt.IsNil(err))

	withCtx(t, func(ctx *azugo.Context) {
		qt.Check(t, qt.IsNil(client.Record(ctx, gdpr.EventDocumentAccess, routineAccess())))
	})
	qt.Assert(t, qt.Equals(ob.Len(), 1))

	go client.Drain(context.Background())
	time.Sleep(10 * time.Millisecond) // let the drainer start

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	qt.Assert(t, qt.IsNil(client.Close(ctx)))
	qt.Check(t, qt.Equals(ob.Len(), 0))
	qt.Check(t, qt.Equals(len(p.accepted()), 1))
}

func TestDeadLetter_ReceivesDropAfterRetriesExhausted(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRetries = 1
	cfg.RetryBackoff = time.Millisecond

	var (
		mu   sync.Mutex
		dead []*broker.Envelope
	)

	done := make(chan struct{})

	p := &fakePoster{alwaysFail: true}
	client, err := gdpr.New(cfg, p, gdpr.Options{
		Outbox: gdpr.NewMemoryOutbox(16),
		DeadLetter: func(rec *broker.Envelope) {
			mu.Lock()
			dead = append(dead, rec)
			mu.Unlock()
			close(done)
		},
	})
	qt.Assert(t, qt.IsNil(err))

	withCtx(t, func(ctx *azugo.Context) {
		qt.Check(t, qt.IsNil(client.Record(ctx, gdpr.EventDocumentAccess, routineAccess())))
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go client.Drain(ctx)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("dropped record never reached the dead-letter sink")
	}

	mu.Lock()
	defer mu.Unlock()
	qt.Assert(t, qt.Equals(len(dead), 1))
	qt.Check(t, qt.Equals(dead[0].EventType, gdpr.EventDocumentAccess))
}

func TestSanitize_CapsLongAttributeValues(t *testing.T) {
	p := &fakePoster{}
	client, err := gdpr.New(testConfig(), p)
	qt.Assert(t, qt.IsNil(err))

	long := strings.Repeat("x", 4*gdpr.MaxAttrValueLen)

	withCtx(t, func(ctx *azugo.Context) {
		a := routineAccess()
		a.Attributes = map[string]any{gdpr.AttrReason: long}
		qt.Check(t, qt.IsNil(client.Record(ctx, gdpr.EventPrivilegedAccess, a)))
	})

	recs := p.accepted()
	qt.Assert(t, qt.Equals(len(recs), 1))

	reason, _ := recs[0].Attributes[gdpr.AttrReason].(string)
	qt.Check(t, qt.Equals(len([]rune(reason)), gdpr.MaxAttrValueLen))
}

func TestFileOutbox_RoundtripOrderAndCrashRecovery(t *testing.T) {
	dir := t.TempDir()

	ob, err := gdpr.NewFileOutbox(dir, 16)
	qt.Assert(t, qt.IsNil(err))

	first := &broker.Envelope{EventID: "ev-1", EventType: gdpr.EventDocumentAccess}
	second := &broker.Envelope{EventID: "ev-2", EventType: gdpr.EventEnvelopeAccess}

	qt.Assert(t, qt.IsNil(ob.Enqueue(first)))
	qt.Assert(t, qt.IsNil(ob.Enqueue(second)))
	qt.Check(t, qt.Equals(ob.Len(), 2))

	// "Crash": reopen the spool directory with a fresh instance.
	reopened, err := gdpr.NewFileOutbox(dir, 16)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(reopened.Len(), 2))

	ctx := context.Background()

	got1, err := reopened.Dequeue(ctx)
	qt.Assert(t, qt.IsNil(err))
	got2, err := reopened.Dequeue(ctx)
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(got1.EventID, "ev-1")) // FIFO survives restart
	qt.Check(t, qt.Equals(got2.EventID, "ev-2"))
	qt.Check(t, qt.Equals(reopened.Len(), 0))

	// Empty + cancelled context → ctx error, no hang.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = reopened.Dequeue(cctx)
	qt.Check(t, qt.ErrorIs(err, context.Canceled))
}

func TestFileOutbox_Full(t *testing.T) {
	ob, err := gdpr.NewFileOutbox(t.TempDir(), 1)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(ob.Enqueue(&broker.Envelope{EventID: "ev-1"})))
	qt.Check(t, qt.ErrorIs(ob.Enqueue(&broker.Envelope{EventID: "ev-2"}), gdpr.ErrOutboxFull))
}
