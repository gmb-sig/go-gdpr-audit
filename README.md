# go-gdpr-audit

The **Regime B** (GDPR personal-data access) audit client for the eSignature Portal. Every
service that touches personal data imports it to record **who accessed whose data, when,
why, and on what lawful basis** — the log that demonstrates GDPR accountability
(Art. 5(2)), answers DSARs (Art. 15), and feeds personal-data-breach detection
(Art. 33/34). It is the client half of the reusable **`access-audit`** service.

See the [Audit Design](../eSignature-Portal-Audit-Design.md) (§4 Regime B, §8, §9) and
[Services Catalog](../eSignature-Portal-Services-Catalog.md) §3.9.8 / §3.10.

Unlike the signing-evidence (Regime A) and security (Regime C) streams, GDPR access records
must be **durably committed and queryable by subject**, so this is a **synchronous client —
not the broker**. Each record is the frozen §8.1 `broker.Envelope` tagged `gdpr_access` and
POSTed synchronously to the `access-audit` service (its own per-system DB) through an
injected **`Poster`**, with a local **outbox + retry** for graceful degradation.

## Delivery policy

| Path | Helpers | On a delivery failure |
|---|---|---|
| **Routine** reads | `Record`, `DocumentAccessed`, `IdentityRead`, `DSARReceived`, … | **buffered** to the outbox + retried; the call returns `nil` (degrades gracefully) |
| **Privileged** / elevated | `RecordPrivileged`, `OperatorAccess`, `Export`, `ErasurePurge`, `DSARFulfilled`, `IdentityDeleted` | **fail-closed**: the call returns an error so the operation can abort |

> **The log is itself PII.** The envelope is kept content-free — only identifiers, the
> operation, and the lawful basis; **never** free-text or document bytes. The client strips
> free-text/content attribute keys defensively and the publisher strips token-shaped keys.
> The calling system/tenant is derived by `access-audit` from the authenticated identity,
> never from the record body.

## Install

```sh
go get github.com/gmb-sig/go-gdpr-audit
```

## Usage

Provide a `Poster` (the authenticated synchronous POST — typically over `go-authbyte`),
construct the client, run `Drain` in the background, and `Flush` on shutdown:

```go
import (
    "github.com/gmb-sig/go-gdpr-audit/gdpr"
    "github.com/gmb-sig/go-platform-kit/broker"
)

client, err := gdpr.New(cfg, poster) // cfg bound from the service's configuration
// ...
go client.Drain(appCtx)              // background delivery of buffered records
defer client.Flush(shutdownCtx)      // best-effort flush on shutdown
```

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

A privileged/break-glass access is *also* a Regime C security event — emit it via
[`go-sec-events`](../go-sec-events) too. Signing-evidence events go through
[`go-eidas-audit`](../go-eidas-audit).

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
| `ACCESS_AUDIT_RETRY_BACKOFF` | `500ms` | Initial drain backoff (doubles, capped). |

The default `MemoryOutbox` is per-pod and non-durable; supply a durable `Outbox` via
`gdpr.Options` where delivery must survive a crash.

## Develop

```sh
go build ./...
go test ./...
go vet ./...
```

## License

MIT — see [LICENSE](./LICENSE).
