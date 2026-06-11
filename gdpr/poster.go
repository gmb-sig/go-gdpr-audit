package gdpr

import (
	"context"

	"github.com/gmb-sig/go-platform-kit/broker"
)

// Poster synchronously delivers one access record to the access-audit service,
// authenticated as the calling service. It is implemented by the consuming
// service — typically over go-authbyte's DPoP-bound PostJSON — so this library
// stays free of a hard transport/auth dependency and is easy to test.
//
// Post must be safe to call from both a request goroutine and the background
// outbox drainer, so it takes a plain context.Context: a request's
// *azugo.Context satisfies it (use a type assertion to reach go-authbyte's
// request-scoped PostJSON), while drained records are posted with a background
// context (acquire the service token via AcquireServiceToken, which also takes a
// context.Context). A non-nil error means the record was NOT persisted; the
// client then buffers (routine) or fails closed (privileged) accordingly.
type Poster interface {
	Post(ctx context.Context, rec *broker.Envelope) error
}

// PosterFunc adapts a function to the Poster interface.
type PosterFunc func(ctx context.Context, rec *broker.Envelope) error

// Post calls f.
func (f PosterFunc) Post(ctx context.Context, rec *broker.Envelope) error {
	return f(ctx, rec)
}
