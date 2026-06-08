package gdpr

import (
	"context"
	"errors"

	"github.com/gmb-sig/go-platform-kit/broker"
)

// ErrOutboxFull is returned by Enqueue when the buffer is at capacity.
var ErrOutboxFull = errors.New("gdpr-audit: outbox is full")

// Outbox is the local fallback buffer for routine access records that could not
// be posted synchronously. The default MemoryOutbox is per-pod and non-durable;
// a service that needs delivery to survive a crash can supply a durable
// implementation (disk/DB-backed) via Options. Implementations must be safe for
// concurrent Enqueue while a single drainer/flusher consumes via Dequeue.
type Outbox interface {
	// Enqueue buffers rec, returning ErrOutboxFull when at capacity.
	Enqueue(rec *broker.Envelope) error
	// Dequeue returns the next buffered record, blocking until one is available
	// or ctx is done (in which case it returns ctx.Err()).
	Dequeue(ctx context.Context) (*broker.Envelope, error)
	// Len reports the number of currently buffered records.
	Len() int
}

// MemoryOutbox is an in-process, bounded Outbox backed by a buffered channel.
type MemoryOutbox struct {
	ch chan *broker.Envelope
}

// NewMemoryOutbox returns a MemoryOutbox holding up to capacity records.
func NewMemoryOutbox(capacity int) *MemoryOutbox {
	if capacity <= 0 {
		capacity = DefaultOutboxCapacity
	}

	return &MemoryOutbox{ch: make(chan *broker.Envelope, capacity)}
}

// Enqueue buffers rec without blocking, returning ErrOutboxFull if the buffer is
// full so the caller can decide whether the loss is acceptable.
func (o *MemoryOutbox) Enqueue(rec *broker.Envelope) error {
	select {
	case o.ch <- rec:
		return nil
	default:
		return ErrOutboxFull
	}
}

// Dequeue returns the next buffered record or ctx.Err() when ctx is done.
func (o *MemoryOutbox) Dequeue(ctx context.Context) (*broker.Envelope, error) {
	select {
	case rec := <-o.ch:
		return rec, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Len reports the number of buffered records.
func (o *MemoryOutbox) Len() int {
	return len(o.ch)
}
