// Package gdpr is the Regime B (GDPR personal-data access) audit client for the
// eSignature Portal. Every service that touches personal data imports it to
// record who accessed whose data, when, why, and on what lawful basis — the log
// that demonstrates GDPR accountability (Art. 5(2)), feeds DSAR responses
// (Art. 15) and personal-data-breach detection (Art. 33/34), and is itself
// subject-indexed so it can answer "every access to this person's data" (Audit
// Design §4, §8; Services Catalog §3.9.8, §3.10).
//
// Unlike the signing-evidence (Regime A) and security (Regime C) streams, GDPR
// access records must be durably committed and queryable by subject, so this is
// a synchronous client — NOT the broker. Each record is the frozen §8.1
// broker.Envelope tagged broker.CategoryGDPRAccess and POSTed synchronously to
// the access-audit service (its own per-system DB) through an injected Poster.
//
// # Delivery policy
//
//   - Routine reads are posted synchronously; on a transient access-audit blip
//     they are buffered to a local Outbox and retried by a background drainer,
//     so a brief outage degrades gracefully (Record / RecordPrivileged false).
//   - Privileged/elevated access (operator break-glass, export, erasure, DSAR
//     fulfilment) is fail-closed: if the record cannot be persisted, the call
//     returns an error so the operation can abort — accountability is not
//     optional for these (RecordPrivileged / the privileged typed helpers).
//
// # PII posture
//
// This log is itself PII (it is about people), so the envelope is kept
// content-free: only identifiers, the operation, and the lawful basis — never
// free-text or document bytes. The client strips free-text/content attribute
// keys defensively, and the publisher strips bearer-token-shaped keys. The
// calling system/tenant is derived by access-audit from the authenticated
// service identity, never from the record body.
package gdpr
