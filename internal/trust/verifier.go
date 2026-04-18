package trust

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EntrySignature is one row from the trust_signatures table.
type EntrySignature struct {
	EntryHash string    `json:"entry_hash"`
	SignerID  string    `json:"signer_id"`
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
}

// Verifier validates ledger entries, individual signatures, and join-request
// signing material.  It queries the DB only for public keys; all crypto is
// done locally.
type Verifier struct {
	db *pgxpool.Pool
}

// NewVerifier creates a Verifier backed by the given connection pool.
func NewVerifier(db *pgxpool.Pool) *Verifier {
	return &Verifier{db: db}
}

// VerifyEntrySignature checks that the Ed25519 signature stored in
// trust_signatures is valid.  The signed message is the raw SHA-256 hash
// bytes of the entry (i.e. base64-decoded entry_hash).
func (v *Verifier) VerifyEntrySignature(ctx context.Context, sig EntrySignature) error {
	pubKey, err := v.publicKeyForNode(ctx, sig.SignerID)
	if err != nil {
		return fmt.Errorf("lookup signer %s: %w", sig.SignerID, err)
	}

	hashBytes, err := base64.StdEncoding.DecodeString(sig.EntryHash)
	if err != nil {
		return fmt.Errorf("decode entry_hash: %w", err)
	}

	ok, err := VerifySignature(pubKey, hashBytes, sig.Signature)
	if err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("signature by node %s on entry %s is invalid",
			sig.SignerID, sig.EntryHash)
	}
	return nil
}

// VerifyJoinRequestSignature verifies a voter's signature over a join request.
//
// The signed message is: SHA256(join_request_id + subject_pubkey + expires_at_rfc3339)
// This matches the specification in the design doc (Step 4 — Voting).
func VerifyJoinRequestSignature(
	voterPubKeyBase64 string,
	joinRequestID string,
	subjectPubKey string,
	expiresAt time.Time,
	sigBase64 string,
) error {
	msg := joinRequestSignedMessage(joinRequestID, subjectPubKey, expiresAt)
	ok, err := VerifySignature(voterPubKeyBase64, msg, sigBase64)
	if err != nil {
		return fmt.Errorf("verify join request signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("join request signature is invalid")
	}
	return nil
}

// SignJoinRequest creates a voter's Ed25519 signature for a join request.
// Returns the base64-encoded signature.
func SignJoinRequest(kp *Keypair, joinRequestID, subjectPubKey string, expiresAt time.Time) string {
	msg := joinRequestSignedMessage(joinRequestID, subjectPubKey, expiresAt)
	return base64.StdEncoding.EncodeToString(kp.Sign(msg))
}

// joinRequestSignedMessage builds the canonical message bytes that are signed
// by a voter approving a join request.
//
//	message = SHA256(join_request_id + subject_pubkey + expires_at_RFC3339Nano)
func joinRequestSignedMessage(joinRequestID, subjectPubKey string, expiresAt time.Time) []byte {
	combined := joinRequestID + subjectPubKey + expiresAt.UTC().Format(time.RFC3339Nano)
	h := sha256.Sum256([]byte(combined))
	return h[:]
}

// VerifyLedgerEntryPayload checks that the payload stored in a ledger entry
// is valid JSON and that the action field within the payload (if present)
// matches the entry's action column.
func VerifyLedgerEntryPayload(entry LedgerEntry) error {
	var payloadMap map[string]json.RawMessage
	if err := json.Unmarshal(entry.Payload, &payloadMap); err != nil {
		return fmt.Errorf("seq %d: payload is not valid JSON: %w", entry.Seq, err)
	}
	if actionRaw, ok := payloadMap["action"]; ok {
		var action string
		if err := json.Unmarshal(actionRaw, &action); err == nil {
			if action != entry.Action {
				return fmt.Errorf("seq %d: payload action %q != column action %q",
					entry.Seq, action, entry.Action)
			}
		}
	}
	return nil
}

// publicKeyForNode fetches the base64-encoded public key for a node by its UUID.
func (v *Verifier) publicKeyForNode(ctx context.Context, nodeID string) (string, error) {
	var pubKey string
	err := v.db.QueryRow(ctx,
		`SELECT public_key FROM nodes WHERE id = $1`, nodeID,
	).Scan(&pubKey)
	if err != nil {
		return "", fmt.Errorf("node not found: %w", err)
	}
	return pubKey, nil
}
