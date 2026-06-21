package gdpr

import (
	"azugo.io/azugo"

	"github.com/gmb-lib/go-platform-kit/broker"
)

// Identity is an identity-record access. LawfulBasis defaults to contract
// (signing) when unset.
type Identity struct {
	Actor       broker.Actor
	SubjectID   string
	LawfulBasis string
	Purpose     string
	Channel     string
}

// IdentityRead records a read of an identity record.
func (c *Client) IdentityRead(ctx *azugo.Context, id Identity) error {
	return c.Record(ctx, EventIdentityRead, id.access(broker.OpRead))
}

// IdentityCreated records the creation of an identity record.
func (c *Client) IdentityCreated(ctx *azugo.Context, id Identity) error {
	return c.Record(ctx, EventIdentityCreated, id.access(broker.OpCreate))
}

// IdentityUpdated records an update to an identity record.
func (c *Client) IdentityUpdated(ctx *azugo.Context, id Identity) error {
	return c.Record(ctx, EventIdentityUpdated, id.access(broker.OpUpdate))
}

// IdentityDeleted records the deletion of an identity record.
func (c *Client) IdentityDeleted(ctx *azugo.Context, id Identity) error {
	return c.RecordPrivileged(ctx, EventIdentityDeleted, id.access(broker.OpDelete))
}

func (id Identity) access(op broker.Operation) Access {
	return Access{
		Actor:        id.Actor,
		DataSubjects: subjects(id.SubjectID),
		Resource:     broker.Resource{Type: ResourceIdentity, ID: id.SubjectID},
		Operation:    op,
		LawfulBasis:  defaultBasis(id.LawfulBasis),
		Purpose:      id.Purpose,
		Channel:      channelOr(id.Channel, ChannelInteractive),
	}
}

// DocumentAccessed records a read/modify of document metadata or bytes —
// including reads by Preview and the Signing Orchestrator. Set Access.Operation,
// LawfulBasis and DataSubjects.
func (c *Client) DocumentAccessed(ctx *azugo.Context, a Access) error {
	if a.Operation == "" {
		a.Operation = broker.OpRead
	}

	a.LawfulBasis = defaultBasis(a.LawfulBasis)

	return c.Record(ctx, EventDocumentAccess, a)
}

// EnvelopeAccessed records a read/modify of envelope / signer-slot personal data.
func (c *Client) EnvelopeAccessed(ctx *azugo.Context, a Access) error {
	if a.Operation == "" {
		a.Operation = broker.OpRead
	}

	a.LawfulBasis = defaultBasis(a.LawfulBasis)

	return c.Record(ctx, EventEnvelopeAccess, a)
}

// CoSigner is a co-signer-invited access — the moment one party's action causes
// processing of another person's data.
type CoSigner struct {
	Actor          broker.Actor
	EnvelopeID     string
	InvitedSubject string
	Channel        string
}

// CoSignerInvited records personal-data processing triggered by inviting a
// co-signer.
func (c *Client) CoSignerInvited(ctx *azugo.Context, cs CoSigner) error {
	return c.Record(ctx, EventCoSignerInvited, Access{
		Actor:        cs.Actor,
		DataSubjects: subjects(cs.InvitedSubject),
		Resource:     broker.Resource{Type: ResourceEnvelope, ID: cs.EnvelopeID},
		Operation:    broker.OpCreate,
		LawfulBasis:  BasisContract,
		Purpose:      PurposeSigning,
		Channel:      channelOr(cs.Channel, ChannelInteractive),
	})
}

// DSAR is a data-subject-access-request lifecycle event.
type DSAR struct {
	Actor     broker.Actor
	SubjectID string
	RequestID string
	Channel   string
}

// DSARReceived records a DSAR being received (Art. 15).
func (c *Client) DSARReceived(ctx *azugo.Context, d DSAR) error {
	return c.Record(ctx, EventDSARReceived, d.access(broker.OpRead))
}

// DSARFulfilled records a DSAR access package being delivered. Fail-closed:
// losing the record of a fulfilled DSAR is not acceptable.
func (c *Client) DSARFulfilled(ctx *azugo.Context, d DSAR) error {
	return c.RecordPrivileged(ctx, EventDSARFulfilled, d.access(broker.OpExport))
}

func (d DSAR) access(op broker.Operation) Access {
	return Access{
		Actor:        d.Actor,
		DataSubjects: subjects(d.SubjectID),
		Resource:     broker.Resource{Type: ResourceIdentity, ID: d.SubjectID},
		Operation:    op,
		LawfulBasis:  BasisLegalObligation,
		Purpose:      PurposeDSARFulfilment,
		Channel:      channelOr(d.Channel, ChannelInteractive),
		Attributes:   map[string]any{AttrRequestID: d.RequestID},
	}
}

// ExportParams is an export of personal data to a recipient.
type ExportParams struct {
	Actor        broker.Actor
	DataSubjects []string
	Resource     broker.Resource
	Recipient    string
	What         string
	LawfulBasis  string
	Purpose      string
	Channel      string
}

// Export records an export of personal data to any recipient. Fail-closed.
func (c *Client) Export(ctx *azugo.Context, e ExportParams) error {
	return c.RecordPrivileged(ctx, EventExport, Access{
		Actor:        e.Actor,
		DataSubjects: e.DataSubjects,
		Resource:     e.Resource,
		Operation:    broker.OpExport,
		LawfulBasis:  defaultBasis(e.LawfulBasis),
		Purpose:      e.Purpose,
		Channel:      channelOr(e.Channel, ChannelInteractive),
		Attributes: map[string]any{
			AttrRecipient: e.Recipient,
			AttrWhat:      e.What,
		},
	})
}

// Erasure is an erasure / retention-purge event (Art. 17).
type Erasure struct {
	Actor             broker.Actor
	DataSubjects      []string
	ResourceType      string
	Count             int
	RetainedUnderHold int
	Channel           string
}

// ErasurePurge records what was deleted and what was retained under legal hold.
// Fail-closed: the fact of deletion is itself retained.
func (c *Client) ErasurePurge(ctx *azugo.Context, er Erasure) error {
	return c.RecordPrivileged(ctx, EventErasurePurge, Access{
		Actor:        er.Actor,
		DataSubjects: er.DataSubjects,
		Resource:     broker.Resource{Type: er.ResourceType},
		Operation:    broker.OpDelete,
		LawfulBasis:  BasisLegalObligation,
		Purpose:      PurposeEvidenceRetention,
		Channel:      channelOr(er.Channel, ChannelBackground),
		Attributes: map[string]any{
			AttrCount:             er.Count,
			AttrRetainedUnderHold: er.RetainedUnderHold,
		},
	})
}

// Operator is an operator / break-glass access to a subject's data.
type Operator struct {
	Actor        broker.Actor
	DataSubjects []string
	Resource     broker.Resource
	Operation    broker.Operation
	Reason       string
	Channel      string
}

// OperatorAccess records elevated operator / break-glass access, flagged
// elevated. Fail-closed. The same action is also a NIS2-audit security event —
// emit it via go-sec-events too.
func (c *Client) OperatorAccess(ctx *azugo.Context, op Operator) error {
	return c.RecordPrivileged(ctx, EventPrivilegedAccess, Access{
		Actor:        op.Actor,
		DataSubjects: op.DataSubjects,
		Resource:     op.Resource,
		Operation:    opOr(op.Operation, broker.OpRead),
		LawfulBasis:  BasisLegitimateInterest,
		Purpose:      PurposeOperations,
		Channel:      channelOr(op.Channel, ChannelInteractive),
		Attributes: map[string]any{
			AttrReason:   op.Reason,
			AttrElevated: true,
		},
	})
}

// defaultBasis falls back to contract (signing) when no basis is given.
func defaultBasis(basis string) string {
	if basis == "" {
		return BasisContract
	}

	return basis
}
