package gdpr

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gmb-lib/go-platform-kit/broker"
)

// FileOutbox is the shipped durable Outbox: each buffered record is one JSON
// file in a spool directory, so buffered routine access records survive a
// crash/redeploy and are re-delivered by the drainer after restart (construct
// the FileOutbox over the same directory). Use it — or a DB-backed Outbox —
// in production instead of the non-durable MemoryOutbox default.
//
// Ordering is FIFO (file names sort by enqueue time). A record is removed from
// disk when Dequeue hands it to the drainer; the only loss window is a crash
// between Dequeue and a successful post, which the drainer narrows further by
// re-enqueueing on cancellation. Corrupted or unreadable spool files are
// skipped, not fatal.
//
// It is safe for concurrent Enqueue with a single Dequeue consumer (the
// Drain/Flush contract). The directory must be private to one client instance;
// two processes must not share a spool directory.
type FileOutbox struct {
	dir      string
	capacity int

	mu     sync.Mutex
	names  []string // FIFO queue of pending spool-file names
	seq    uint64
	notify chan struct{}
}

const spoolSuffix = ".json"

// NewFileOutbox opens (creating if needed) the spool directory dir, recovers
// any records left over from a previous run, and returns a durable Outbox
// holding up to capacity records (DefaultOutboxCapacity when capacity <= 0).
func NewFileOutbox(dir string, capacity int) (*FileOutbox, error) {
	if capacity <= 0 {
		capacity = DefaultOutboxCapacity
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("gdpr-audit: create outbox spool dir: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("gdpr-audit: read outbox spool dir: %w", err)
	}

	var names []string

	for _, e := range entries {
		if e.IsDir() {
			continue
		}

		name := e.Name()

		// Clean up incomplete writes from a previous crash.
		if strings.HasSuffix(name, ".tmp") {
			_ = os.Remove(filepath.Join(dir, name))

			continue
		}

		if strings.HasSuffix(name, spoolSuffix) {
			names = append(names, name)
		}
	}

	sort.Strings(names) // zero-padded timestamps → enqueue order

	return &FileOutbox{dir: dir, capacity: capacity, names: names, notify: make(chan struct{}, 1)}, nil
}

// Enqueue durably buffers rec (write-to-temp + rename), returning ErrOutboxFull
// when at capacity.
func (o *FileOutbox) Enqueue(rec *broker.Envelope) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("gdpr-audit: marshal outbox record: %w", err)
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	if len(o.names) >= o.capacity {
		return ErrOutboxFull
	}

	o.seq++
	name := fmt.Sprintf("%020d-%06d%s", time.Now().UnixNano(), o.seq, spoolSuffix)

	tmp := filepath.Join(o.dir, name+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("gdpr-audit: write outbox record: %w", err)
	}

	if err := os.Rename(tmp, filepath.Join(o.dir, name)); err != nil {
		_ = os.Remove(tmp)

		return fmt.Errorf("gdpr-audit: commit outbox record: %w", err)
	}

	o.names = append(o.names, name)

	select {
	case o.notify <- struct{}{}:
	default:
	}

	return nil
}

// Dequeue returns the next buffered record (removing it from the spool),
// blocking until one is available or ctx is done. Corrupted spool files are
// skipped.
func (o *FileOutbox) Dequeue(ctx context.Context) (*broker.Envelope, error) {
	for {
		o.mu.Lock()

		for len(o.names) > 0 {
			name := o.names[0]
			o.names = o.names[1:]

			path := filepath.Join(o.dir, name)

			data, err := os.ReadFile(path)
			_ = os.Remove(path)

			if err != nil {
				continue // unreadable: skip, try the next one
			}

			rec := &broker.Envelope{}
			if err := json.Unmarshal(data, rec); err != nil {
				continue // corrupted: skip, try the next one
			}

			o.mu.Unlock()

			return rec, nil
		}

		o.mu.Unlock()

		select {
		case <-o.notify:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Len reports the number of currently buffered records.
func (o *FileOutbox) Len() int {
	o.mu.Lock()
	defer o.mu.Unlock()

	return len(o.names)
}
