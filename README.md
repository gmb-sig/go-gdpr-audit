# go-gdpr-audit

The **GDPR-audit** (GDPR personal-data access) audit client for eIDAS signing services. Every
service that touches personal data imports it to record **who accessed whose data, when,
why, and on what lawful basis** — the log that demonstrates GDPR accountability
(Art. 5(2)), answers DSARs (Art. 15), and feeds personal-data-breach detection
(Art. 33/34). It is the client half of the reusable **`access-audit`** service.

**Scope:** this library targets [Azugo](https://azugo.io) services — its helper entrypoints
take `*azugo.Context` by design (the transport-level `Poster` is stack-agnostic).
`DataSubjects` values must be **pseudonymous internal identity references**, never national
identifiers, names, or e-mail addresses.

Unlike the signing-evidence (eIDAS-audit) and security (NIS2-audit) streams, GDPR access records
must be **durably committed and queryable by subject**, so this is a **synchronous client —
not the broker**. Each record is the frozen `broker.Envelope` tagged `gdpr_access` and
POSTed synchronously to the `access-audit` service (its own per-system DB) through an
injected **`Poster`**, with a local **outbox + retry** for graceful degradation.

## Delivery policy

| Path | Helpers | On a delivery failure |
|---|---|---|
| **Routine** reads | `Record`, `DocumentAccessed`, `IdentityRead`, `DSARReceived`, … | **buffered** to the outbox + retried; the call returns `nil` (degrades gracefully) |
| **Privileged** / elevated | `RecordPrivileged`, `OperatorAccess`, `Export`, `ErasurePurge`, `DSARFulfilled`, `IdentityDeleted` | **fail-closed**: the call returns an error so the operation can abort |

Every post is bounded by the configured **timeout (enforced per post)**; drain retries use
**jittered exponential backoff**; and a **circuit breaker** buffers routine records
immediately while the sink is slow/failing (privileged posts always attempt). Records that
cannot be persisted or buffered are handed to the optional **`DeadLetter`** sink before
being dropped.

> **Back-pressure contract.** On a sustained outage the routine path progresses
> sync → buffered → buffer-full → **error**. Treat routine-record errors as **non-fatal**
> for the user operation (log + continue) and alert on the `dropped` outcome of
> `gdpr_audit_records_total` instead — failing user reads on audit back-pressure inverts
> the graceful-degradation design.

> **The log is itself PII.** The envelope carries only identifiers, the operation, the
> lawful basis, and **bounded operational metadata** — never document content or unbounded
> free text. The client strips content-bearing attribute keys defensively and truncates
> every string attribute value to `MaxAttrValueLen` (256) runes, which bounds the permitted
> operational fields (`reason` / `what` / `recipient` — a ticket number, not a narrative);
> the publisher strips token-shaped keys. The calling system/tenant is derived by
> `access-audit` from the authenticated identity, never from the record body.

## Install

```sh
go get github.com/gmb-sig/go-gdpr-audit
```

## Usage

Provide a `Poster` (the authenticated synchronous POST — typically over `go-authbyte`),
construct the client with a **durable outbox**, run `Drain` in the background, and call
`Close` on shutdown (it stops the drainer and flushes, in the right order):

```go
import (
    "github.com/gmb-sig/go-gdpr-audit/gdpr"
    "github.com/gmb-lib/go-platform-kit/broker"
)

outbox, err := gdpr.NewFileOutbox("/var/spool/gdpr-audit", 1024) // survives crash/redeploy
// ...
client, err := gdpr.New(cfg, poster, gdpr.Options{ // cfg bound from the service's configuration
    Outbox:     outbox,
    DeadLetter: func(rec *broker.Envelope) { /* persist out-of-band */ },
    Logger:     logger,
})
// ...
go client.Drain(appCtx)         // background delivery of buffered records
defer client.Close(shutdownCtx) // stop drainer + flush, atomically ordered
```

Without `Options.Outbox` the client falls back to the **non-durable** in-memory buffer and
logs a warning — fine for dev, not for production.

Record accesses with the typed helpers — the event type, operation, lawful basis and
fail-policy are set for you:

```go
// Routine read (buffers on a transient blip):
client.DocumentAccessed(ctx, gdpr.Access{
    Actor:        broker.Actor{ID: ctx.User().ID(), Type: "user"},
    DataSubjects: []string{signerID},
    Resource:     broker.Resource{Type: gdpr.ResourceDocument, ID: docID},
    Operation:    broker.OpRead,
    LawfulBasis:  gdpr.BasisContract,
    Purpose:      gdpr.PurposeSigning,
    Channel:      gdpr.ChannelInteractive,
})

// Elevated access — fail-closed: abort the request if it can't be logged:
if err := client.OperatorAccess(ctx, gdpr.Operator{
    Actor:        broker.Actor{ID: operatorID, Type: "user"},
    DataSubjects: []string{subjectID},
    Resource:     broker.Resource{Type: gdpr.ResourceDocument, ID: docID},
    Reason:       "support ticket #42",
}); err != nil {
    return err // do not proceed with the privileged read
}
```

### Implementing the Poster

`Poster.Post(ctx context.Context, rec *broker.Envelope) error` is the authenticated POST to
`access-audit`. The request path receives the request's `*azugo.Context`; drained records
are posted with a background context. A typical adapter over `go-authbyte`:

```go
type accessAuditPoster struct {
    auth *authclient.Client
    cfg  gdpr.Configuration
}

func (p accessAuditPoster) Post(ctx context.Context, rec *broker.Envelope) error {
    url := strings.TrimSuffix(p.cfg.Endpoint, "/") + "/v1/access-records"
    // Request path: reuse go-authbyte's DPoP-bound, service-token POST.
    if ac, ok := ctx.(*azugo.Context); ok {
        return p.auth.PostJSON(ac, p.cfg.Audience, p.cfg.Scope, url, rec, nil)
    }
    // Background drain: acquire a service token with the plain context and POST.
    // (token := p.auth.AcquireServiceToken(ctx, p.cfg.Audience, p.cfg.Scope) …)
    return p.postBackground(ctx, url, rec)
}
```

## Events

| Helper | `event_type` | Policy |
|---|---|---|
| `IdentityRead` / `Created` / `Updated` | `identity.*` | routine |
| `IdentityDeleted` | `identity.deleted` | fail-closed |
| `DocumentAccessed` | `document.access` | routine |
| `EnvelopeAccessed` | `envelope.access` | routine |
| `CoSignerInvited` | `envelope.cosigner_invited` | routine |
| `DSARReceived` | `dsar.received` | routine |
| `DSARFulfilled` | `dsar.fulfilled` | fail-closed |
| `Export` | `data.export` | fail-closed |
| `ErasurePurge` | `erasure.purge` | fail-closed |
| `OperatorAccess` | `access.privileged` | fail-closed |
| `Record` / `RecordPrivileged` | *(any)* | routine / fail-closed |

A privileged/break-glass access is *also* a NIS2-audit security event — emit it via
[`go-sec-events`](https://github.com/gmb-sig/go-sec-events) too. Signing-evidence events go through
[`go-eidas-audit`](https://github.com/gmb-sig/go-eidas-audit).

## Configuration

Bound as a sub-configuration of the consuming service:

| Env | Default | Purpose |
|---|---|---|
| `ACCESS_AUDIT_URL` | — | `access-audit` base URL (used by the Poster). |
| `ACCESS_AUDIT_AUDIENCE` | — | `access-audit` service `aud` for the outbound token. |
| `ACCESS_AUDIT_SCOPE` | — | OAuth scope for the write call. |
| `ACCESS_AUDIT_TIMEOUT` | `5s` | Per-post timeout. |
| `ACCESS_AUDIT_OUTBOX_CAPACITY` | `1024` | Local fallback buffer size. |
| `ACCESS_AUDIT_MAX_RETRIES` | `5` | Drain retry attempts per buffered record. |
| `ACCESS_AUDIT_RETRY_BACKOFF` | `500ms` | Initial drain backoff (doubles, capped, jittered). |
| `ACCESS_AUDIT_BREAKER_THRESHOLD` | `3` | Consecutive failures that trip the breaker (`0` disables). |
| `ACCESS_AUDIT_BREAKER_COOLDOWN` | `10s` | How long the breaker stays open before re-probing. |

The default `MemoryOutbox` is per-pod and **non-durable**; production services should use
`gdpr.NewFileOutbox` (shipped, disk-backed, crash-recovering) or a DB-backed `Outbox`, plus
a `DeadLetter` sink for records dropped after retries.

## Develop

```sh
go build ./...
go test ./...
go vet ./...
```

## License

MIT — see [LICENSE](./LICENSE).
