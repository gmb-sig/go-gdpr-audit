// Package gdpr is the GDPR-audit (GDPR personal-data access) audit client for
// eIDAS signing services. Every service that touches personal data imports it to
// record who accessed whose data, when, why, and on what lawful basis — the log
// that demonstrates GDPR accountability (Art. 5(2)), feeds DSAR responses
// (Art. 15) and personal-data-breach detection (Art. 33/34), and is itself
// subject-indexed so it can answer "every access to this person's data".
//
// Unlike the signing-evidence (eIDAS-audit) and security (NIS2-audit) streams, GDPR
// access records must be durably committed and queryable by subject, so this is
// a synchronous client — NOT the broker. Each record is the frozen
// broker.Envelope tagged broker.CategoryGDPRAccess and POSTed synchronously to
// the access-audit service (its own per-system DB) through an injected Poster.
//
// # Delivery policy
//
// - Routine reads are posted synchronously (bounded by the configured
// Timeout, enforced per post); on a transient access-audit failure they are
// buffered to a local Outbox and retried by a background drainer with
// jittered backoff, so a brief outage degrades gracefully. A circuit
// breaker (BreakerThreshold/BreakerCooldown) protects interactive latency
// against a slow-but-up sink by buffering immediately while open.
// - Privileged/elevated access (operator break-glass, export, erasure, DSAR
// fulfilment) is fail-closed: if the record cannot be persisted, the call
// returns an error so the operation can abort — accountability is not
// optional for these (RecordPrivileged / the privileged typed helpers).
// Privileged posts always attempt delivery, breaker or not.
//
// # Back-pressure contract (read this)
//
// On a sustained outage the routine path progresses sync → buffered →
// buffer-full → error: once the Outbox is at capacity, Record starts returning
// errors. Callers MUST treat routine-record errors as non-fatal for the user
// operation (log + continue) — failing user reads on audit back-pressure
// inverts the graceful-degradation design. Alert on the `dropped` outcome of
// MetricRecordsTotal instead. Dropped records are handed to the optional
// DeadLetter sink before being discarded.
//
// # Durability
//
// The default MemoryOutbox is per-pod and non-durable: a crash loses buffered
// records. Production services should supply the shipped disk-backed
// FileOutbox (or a DB-backed Outbox) via Options, and/or a DeadLetter sink.
// New logs a warning when the lossy default is used.
//
// # Lifecycle
//
// Run the drainer once in the background (go client.Drain(appCtx)) and call
// client.Close(ctx) on shutdown — Close stops the drainer, waits for it, and
// flushes the outbox in the correct order, replacing the error-prone manual
// "cancel Drain, then Flush" sequence.
//
// # PII posture
//
// This log is itself PII (it is about people), so the envelope carries only
// identifiers, the operation, the lawful basis, and bounded operational
// metadata — never document content or unbounded free text. Concretely: the
// client strips content-bearing attribute keys defensively, truncates every
// string attribute value to MaxAttrValueLen runes (this bounds the permitted
// operational fields AttrReason / AttrWhat / AttrRecipient), and the publisher
// strips bearer-token-shaped keys. Callers must still not put personal data in
// those fields ("support ticket #42", not the customer's story). The calling
// system/tenant is derived by access-audit from the authenticated service
// identity, never from the record body.
package gdpr
