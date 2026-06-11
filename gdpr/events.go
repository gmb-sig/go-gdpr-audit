package gdpr

// Event types for Regime B personal-data access events (Audit Design §4, §7).
const (
	// EventIdentityRead / Created / Updated / Deleted — identity-record access.
	EventIdentityRead    = "identity.read"
	EventIdentityCreated = "identity.created"
	EventIdentityUpdated = "identity.updated"
	EventIdentityDeleted = "identity.deleted"
	// EventDocumentAccess — document metadata or bytes accessed.
	EventDocumentAccess = "document.access"
	// EventEnvelopeAccess — envelope / signer-slot personal data read or modified.
	EventEnvelopeAccess = "envelope.access"
	// EventCoSignerInvited — one party's action causes processing of another's
	// personal data.
	EventCoSignerInvited = "envelope.cosigner_invited"
	// EventDSARReceived / Fulfilled — DSAR lifecycle (Art. 15).
	EventDSARReceived  = "dsar.received"
	EventDSARFulfilled = "dsar.fulfilled"
	// EventErasurePurge — erasure / retention purge (Art. 17); the fact of
	// deletion is itself retained.
	EventErasurePurge = "erasure.purge"
	// EventExport — export of personal data to any recipient.
	EventExport = "data.export"
	// EventPrivilegedAccess — operator / break-glass access, flagged elevated.
	EventPrivilegedAccess = "access.privileged"
	// EventConsentChange — consent / processing-basis change, where applicable.
	EventConsentChange = "consent.change"
)

// Lawful basis under GDPR Art. 6. Recorded on every access so the log can
// demonstrate the basis the processing relied on.
const (
	BasisContract           = "contract"            // contract performance — signing
	BasisLegalObligation    = "legal_obligation"    // evidence retention, DSAR
	BasisConsent            = "consent"             //
	BasisLegitimateInterest = "legitimate_interest" // e.g. fraud prevention, operations
	BasisPublicTask         = "public_task"         //
	BasisVitalInterest      = "vital_interest"      //
)

// Purpose values pair with the lawful basis to explain *why* the data was
// processed.
const (
	PurposeSigning           = "signing"
	PurposeEvidenceRetention = "evidence_retention"
	PurposeDSARFulfilment    = "dsar_fulfilment"
	PurposeAccountManagement = "account_management"
	PurposeOperations        = "operations"
)

// Access channel — interactive user vs background job (Audit Design §4).
const (
	ChannelInteractive = "interactive"
	ChannelBackground  = "background"
)

// Resource types the access concerns.
const (
	ResourceDocument = "document"
	ResourceEnvelope = "envelope"
	ResourceIdentity = "identity"
)

// Attribute keys. Identifiers and bounded operational metadata only — never
// document content or unbounded free text. String values are truncated to
// MaxAttrValueLen runes by the client; AttrReason / AttrWhat / AttrRecipient
// are short operational references (e.g. a ticket number), not narratives.
const (
	AttrChannel           = "channel"
	AttrRecipient         = "recipient"
	AttrWhat              = "what"
	AttrRequestID         = "request_id"
	AttrCount             = "count"
	AttrRetainedUnderHold = "retained_under_hold"
	AttrElevated          = "elevated"
	AttrReason            = "reason"
)
