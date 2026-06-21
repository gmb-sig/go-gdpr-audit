package gdpr_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-sig/go-gdpr-audit/gdpr"
)

// fakePoster is a controllable Poster: it can fail the first failUntil calls (or
// always), records what it accepts, and can signal the first success.
type fakePoster struct {
	mu         sync.Mutex
	records    []*broker.Envelope
	calls      int
	failUntil  int
	alwaysFail bool
	signal     chan struct{}
	signaled   bool
}

func (p *fakePoster) Post(_ context.Context, rec *broker.Envelope) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls++
	if p.alwaysFail || p.calls <= p.failUntil {
		return errors.New("access-audit unavailable")
	}

	p.records = append(p.records, rec)

	if p.signal != nil && !p.signaled {
		p.signaled = true
		close(p.signal)
	}

	return nil
}

func (p *fakePoster) accepted() []*broker.Envelope {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]*broker.Envelope(nil), p.records...)
}

func (p *fakePoster) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.calls
}

func testConfig() gdpr.Configuration {
	return gdpr.Configuration{
		Endpoint:       "http://access-audit:8080",
		Audience:       "svc:access-audit",
		Scope:          "access-audit:write",
		Timeout:        time.Second,
		OutboxCapacity: 16,
		MaxRetries:     5,
		RetryBackoff:   time.Millisecond,
	}
}

func withCtx(t *testing.T, fn func(ctx *azugo.Context)) {
	t.Helper()

	app := azugo.NewTestApp()
	app.Get("/t", func(ctx *azugo.Context) {
		fn(ctx)
		ctx.StatusCode(fasthttp.StatusNoContent)
	})
	app.Start(t)

	defer app.Stop()

	resp, err := app.TestClient().Get("/t")
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)
}

func TestRecord_RoutineSuccess(t *testing.T) {
	p := &fakePoster{}
	client, err := gdpr.New(testConfig(), p)
	qt.Assert(t, qt.IsNil(err))

	var rerr error

	withCtx(t, func(ctx *azugo.Context) {
		rerr = client.DocumentAccessed(ctx, gdpr.Access{
			Actor:        broker.Actor{ID: "user-1", Type: "user"},
			DataSubjects: []string{"subject-1"},
			Resource:     broker.Resource{Type: gdpr.ResourceDocument, ID: "doc-1"},
			Operation:    broker.OpRead,
			LawfulBasis:  gdpr.BasisContract,
			Purpose:      gdpr.PurposeSigning,
			Channel:      gdpr.ChannelInteractive,
		})
	})

	qt.Assert(t, qt.IsNil(rerr))

	recs := p.accepted()
	qt.Assert(t, qt.Equals(len(recs), 1))

	rec := recs[0]
	qt.Check(t, qt.Equals(rec.EventType, gdpr.EventDocumentAccess))
	qt.Check(t, qt.Equals(len(rec.Categories), 1))
	qt.Check(t, qt.Equals(rec.Categories[0], broker.CategoryGDPRAccess))
	qt.Check(t, qt.Equals(rec.Operation, broker.OpRead))
	qt.Check(t, qt.Equals(rec.LawfulBasis, gdpr.BasisContract))
	qt.Check(t, qt.Equals(len(rec.DataSubjects), 1))
	qt.Check(t, qt.Equals(rec.DataSubjects[0], "subject-1"))
	qt.Check(t, qt.Equals(str(rec.Attributes[gdpr.AttrChannel]), gdpr.ChannelInteractive))
	qt.Check(t, qt.Not(qt.Equals(rec.EventID, ""))) // stamped
}

func TestRecord_RoutineBuffersOnFailure(t *testing.T) {
	p := &fakePoster{alwaysFail: true}
	ob := gdpr.NewMemoryOutbox(16)
	client, err := gdpr.New(testConfig(), p, gdpr.Options{Outbox: ob})
	qt.Assert(t, qt.IsNil(err))

	var rerr error

	withCtx(t, func(ctx *azugo.Context) {
		rerr = client.DocumentAccessed(ctx, gdpr.Access{
			DataSubjects: []string{"subject-1"},
			Resource:     broker.Resource{Type: gdpr.ResourceDocument, ID: "doc-1"},
			LawfulBasis:  gdpr.BasisContract,
		})
	})

	// Routine read degrades gracefully: buffered, no error to the caller.
	qt.Assert(t, qt.IsNil(rerr))
	qt.Check(t, qt.Equals(ob.Len(), 1))
}

func TestRecordPrivileged_FailsClosed(t *testing.T) {
	p := &fakePoster{alwaysFail: true}
	ob := gdpr.NewMemoryOutbox(16)
	client, err := gdpr.New(testConfig(), p, gdpr.Options{Outbox: ob})
	qt.Assert(t, qt.IsNil(err))

	var rerr error

	withCtx(t, func(ctx *azugo.Context) {
		rerr = client.OperatorAccess(ctx, gdpr.Operator{
			Actor:        broker.Actor{ID: "op-1", Type: "user"},
			DataSubjects: []string{"subject-1"},
			Resource:     broker.Resource{Type: gdpr.ResourceDocument, ID: "doc-1"},
			Reason:       "support ticket #42",
		})
	})

	// Privileged access is fail-closed: the caller gets an error and the record
	// is NOT silently buffered.
	qt.Assert(t, qt.IsNotNil(rerr))
	qt.Check(t, qt.Equals(ob.Len(), 0))
}

func TestRecord_MissingLawfulBasisRejected(t *testing.T) {
	p := &fakePoster{}
	client, err := gdpr.New(testConfig(), p)
	qt.Assert(t, qt.IsNil(err))

	var rerr error

	withCtx(t, func(ctx *azugo.Context) {
		rerr = client.Record(ctx, gdpr.EventDocumentAccess, gdpr.Access{
			DataSubjects: []string{"subject-1"},
			Operation:    broker.OpRead,
			// LawfulBasis intentionally omitted
		})
	})

	qt.Check(t, qt.ErrorIs(rerr, gdpr.ErrMissingLawfulBasis))
	qt.Check(t, qt.Equals(p.callCount(), 0)) // never attempted
}

func TestRecord_SanitizesContentAndTokens(t *testing.T) {
	p := &fakePoster{}
	client, err := gdpr.New(testConfig(), p)
	qt.Assert(t, qt.IsNil(err))

	withCtx(t, func(ctx *azugo.Context) {
		_ = client.Record(ctx, gdpr.EventDocumentAccess, gdpr.Access{
			DataSubjects: []string{"subject-1"},
			Operation:    broker.OpRead,
			LawfulBasis:  gdpr.BasisContract,
			Attributes: map[string]any{
				"document_bytes": "%PDF",   // content — must go
				"free_text_note": "secret", // free text — must go
				"dpop_proof":     "eyJ...", // token — must go
				"request_id":     "req-7",  // safe identifier — must stay
			},
		})
	})

	recs := p.accepted()
	qt.Assert(t, qt.Equals(len(recs), 1))

	attrs := recs[0].Attributes
	for _, gone := range []string{"document_bytes", "free_text_note", "dpop_proof"} {
		_, present := attrs[gone]
		qt.Check(t, qt.IsFalse(present), qt.Commentf("attribute %q must be stripped", gone))
	}

	qt.Check(t, qt.Equals(str(attrs["request_id"]), "req-7"))
}

func TestDrain_DeliversBufferedRecord(t *testing.T) {
	// Fail only the first (synchronous) post so the record is buffered, then let
	// the background drainer deliver it.
	p := &fakePoster{failUntil: 1, signal: make(chan struct{})}
	client, err := gdpr.New(testConfig(), p)
	qt.Assert(t, qt.IsNil(err))

	withCtx(t, func(ctx *azugo.Context) {
		qt.Check(t, qt.IsNil(client.DocumentAccessed(ctx, gdpr.Access{
			DataSubjects: []string{"subject-1"},
			LawfulBasis:  gdpr.BasisContract,
		})))
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go client.Drain(ctx)

	select {
	case <-p.signal:
		// delivered on retry
	case <-time.After(2 * time.Second):
		t.Fatal("buffered record was not drained")
	}

	qt.Check(t, qt.Equals(len(p.accepted()), 1))
}

func TestFlush_DeliversBufferedRecords(t *testing.T) {
	// First two posts fail (the two synchronous attempts), so both records are
	// buffered; Flush then delivers them once the poster recovers.
	p := &fakePoster{failUntil: 2}
	ob := gdpr.NewMemoryOutbox(16)
	client, err := gdpr.New(testConfig(), p, gdpr.Options{Outbox: ob})
	qt.Assert(t, qt.IsNil(err))

	withCtx(t, func(ctx *azugo.Context) {
		for i := 0; i < 2; i++ {
			qt.Check(t, qt.IsNil(client.DocumentAccessed(ctx, gdpr.Access{
				DataSubjects: []string{"subject-1"},
				LawfulBasis:  gdpr.BasisContract,
			})))
		}
	})

	qt.Assert(t, qt.Equals(ob.Len(), 2))

	qt.Assert(t, qt.IsNil(client.Flush(context.Background())))
	qt.Check(t, qt.Equals(ob.Len(), 0))
	qt.Check(t, qt.Equals(len(p.accepted()), 2))
}

func TestErasurePurge_CarriesCounts(t *testing.T) {
	p := &fakePoster{}
	client, err := gdpr.New(testConfig(), p)
	qt.Assert(t, qt.IsNil(err))

	withCtx(t, func(ctx *azugo.Context) {
		qt.Check(t, qt.IsNil(client.ErasurePurge(ctx, gdpr.Erasure{
			Actor:             broker.Actor{ID: "svc:document", Type: "service"},
			ResourceType:      gdpr.ResourceDocument,
			Count:             12,
			RetainedUnderHold: 3,
		})))
	})

	recs := p.accepted()
	qt.Assert(t, qt.Equals(len(recs), 1))
	qt.Check(t, qt.Equals(recs[0].EventType, gdpr.EventErasurePurge))
	qt.Check(t, qt.Equals(recs[0].Operation, broker.OpDelete))
	qt.Check(t, qt.Equals(toInt(recs[0].Attributes[gdpr.AttrCount]), 12))
	qt.Check(t, qt.Equals(str(recs[0].Attributes[gdpr.AttrChannel]), gdpr.ChannelBackground))
}

func TestNew_RequiresPoster(t *testing.T) {
	_, err := gdpr.New(testConfig(), nil)
	qt.Check(t, qt.ErrorIs(err, gdpr.ErrNotConfigured))
}

func str(v any) string {
	s, _ := v.(string)

	return s
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return -1
	}
}
