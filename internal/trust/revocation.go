package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Revocation manages the threshold-based revocation voting lifecycle.
//
// Flow per design doc:
//
//	Tier 1 (genesis): unilateral — ProposeRevocation immediately executes (threshold=1)
//	Tier 2 (trusted nodes): ProposeRevocation (first vote) → AddRevocationVote (more votes)
//	  → when threshold met → executeRevocation runs automatically
//
// SUSPEND:   threshold_suspend   (default 2)
// BAN:       threshold_ban       (default 3)
// REINSTATE: threshold_reinstate (default 3)
type Revocation struct {
	db     *pgxpool.Pool
	ledger *Ledger
	gossip *Gossip
}

// RevocationProposal represents a row from the revocation_proposals table.
type RevocationProposal struct {
	ID                   string
	SubjectID            string
	Action               string // "suspend", "ban", "reinstate"
	Reason               string
	Status               string // "voting", "executed", "rejected", "expired"
	Votes                int
	RequiredVotes        int
	SuspendDurationHours int // 0 = indefinite; only used when Action="suspend"
	ExpiresAt            time.Time
	CreatedAt            time.Time
}

// NewRevocation creates a Revocation manager.
func NewRevocation(db *pgxpool.Pool, ledger *Ledger, gossip *Gossip) *Revocation {
	return &Revocation{db: db, ledger: ledger, gossip: gossip}
}

// ProposeRevocation opens a new revocation proposal and records the proposer's
// vote. If the proposer is the genesis node (role='genesis'), required_votes=1
// and the action executes immediately.
//
// suspendDurationHours is only meaningful when action="suspend":
//   - 0 = indefinite suspension (manual reinstate required)
//   - >0 = auto-reinstate after that many hours
//
// Returns proposalID and whether it was already executed (genesis unilateral).
func (r *Revocation) ProposeRevocation(
	ctx context.Context,
	subjectNodeID, actorNodeID, action, reason string,
	suspendDurationHours int,
	netCfg NetworkConfig,
) (proposalID string, executed bool, err error) {
	if action != "suspend" && action != "ban" && action != "reinstate" {
		return "", false, fmt.Errorf("invalid revocation action: %s", action)
	}

	// Subject must be in a valid state for this action.
	var subjectStatus string
	if err = r.db.QueryRow(ctx,
		`SELECT status FROM nodes WHERE id = $1`, subjectNodeID,
	).Scan(&subjectStatus); err != nil {
		return "", false, fmt.Errorf("subject node not found: %w", err)
	}
	if action == "reinstate" && subjectStatus != "suspended" {
		return "", false, fmt.Errorf("node is not suspended (status: %s)", subjectStatus)
	}
	if (action == "suspend" || action == "ban") && subjectStatus != "active" && subjectStatus != "suspended" {
		return "", false, fmt.Errorf("cannot %s node with status: %s", action, subjectStatus)
	}

	// Genesis node acts unilaterally (required_votes=1), everyone else uses
	// the genesis-config threshold.
	var actorRole string
	if err = r.db.QueryRow(ctx,
		`SELECT role FROM nodes WHERE id = $1`, actorNodeID,
	).Scan(&actorRole); err != nil {
		return "", false, fmt.Errorf("actor node not found: %w", err)
	}
	requiredVotes := r.thresholdForAction(action, netCfg)
	if actorRole == "genesis" {
		requiredVotes = 1
	}

	// Adaptive: effective = min(configured, active_nodes).
	var activeCount int
	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM nodes WHERE status = 'active'`,
	).Scan(&activeCount)
	if activeCount > 0 && activeCount < requiredVotes {
		requiredVotes = activeCount
	}
	if requiredVotes < 1 {
		requiredVotes = 1
	}

	// Reject if an open proposal already exists for the same subject + action.
	var existingID string
	lookupErr := r.db.QueryRow(ctx, `
		SELECT id FROM revocation_proposals
		WHERE subject_id = $1::uuid AND action = $2 AND status = 'voting'`,
		subjectNodeID, action,
	).Scan(&existingID)
	if lookupErr == nil {
		return "", false, fmt.Errorf(
			"revocation proposal for this action already open (id: %s)", existingID)
	}
	if !errors.Is(lookupErr, pgx.ErrNoRows) {
		return "", false, fmt.Errorf("check existing proposal: %w", lookupErr)
	}

	// Create the proposal.
	id, err := newUUID()
	if err != nil {
		return "", false, fmt.Errorf("generate proposal id: %w", err)
	}
	expires := time.Now().UTC().Add(72 * time.Hour)

	var durationArg *int
	if action == "suspend" && suspendDurationHours > 0 {
		durationArg = &suspendDurationHours
	}

	if _, err = r.db.Exec(ctx, `
		INSERT INTO revocation_proposals
		    (id, subject_id, action, reason, required_votes, suspend_duration_hours, expires_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)`,
		id, subjectNodeID, action, reason, requiredVotes, durationArg, expires,
	); err != nil {
		return "", false, fmt.Errorf("insert revocation proposal: %w", err)
	}

	// Record the proposer's vote (first vote — may immediately hit threshold=1).
	executed, err = r.AddRevocationVote(ctx, id, actorNodeID, netCfg)
	if err != nil {
		return id, false, fmt.Errorf("record first vote: %w", err)
	}
	return id, executed, nil
}

// AddRevocationVote records one vote on an open proposal. When the vote tips
// the count to the required threshold, executeRevocation is called automatically.
// Returns true if the action was executed as a result of this vote.
func (r *Revocation) AddRevocationVote(
	ctx context.Context,
	proposalID, voterNodeID string,
	netCfg NetworkConfig,
) (executed bool, err error) {
	var p RevocationProposal
	var durationHours *int
	if err = r.db.QueryRow(ctx, `
		SELECT id, subject_id, action, COALESCE(reason,''), status, votes, required_votes,
		       suspend_duration_hours, expires_at
		FROM revocation_proposals WHERE id = $1::uuid`,
		proposalID,
	).Scan(&p.ID, &p.SubjectID, &p.Action, &p.Reason,
		&p.Status, &p.Votes, &p.RequiredVotes, &durationHours, &p.ExpiresAt,
	); err != nil {
		return false, fmt.Errorf("proposal not found: %w", err)
	}
	if durationHours != nil {
		p.SuspendDurationHours = *durationHours
	}
	if p.Status != "voting" {
		return false, fmt.Errorf("proposal is not open for voting (status: %s)", p.Status)
	}
	if time.Now().After(p.ExpiresAt) {
		_, _ = r.db.Exec(ctx,
			`UPDATE revocation_proposals SET status = 'expired' WHERE id = $1::uuid`, proposalID)
		return false, fmt.Errorf("proposal has expired")
	}

	// Voter must be active.
	var voterStatus string
	if err = r.db.QueryRow(ctx,
		`SELECT status FROM nodes WHERE id = $1`, voterNodeID,
	).Scan(&voterStatus); err != nil {
		return false, fmt.Errorf("voter node not found: %w", err)
	}
	if voterStatus != "active" {
		return false, fmt.Errorf("voter node is not active (status: %s)", voterStatus)
	}

	// Prevent double-vote.
	var alreadyVoted bool
	_ = r.db.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM revocation_votes
		WHERE proposal_id = $1::uuid AND voter_id = $2::uuid)`,
		proposalID, voterNodeID,
	).Scan(&alreadyVoted)
	if alreadyVoted {
		return false, fmt.Errorf("node %s has already voted on this proposal", voterNodeID)
	}

	// Record vote.
	if _, err = r.db.Exec(ctx, `
		INSERT INTO revocation_votes (proposal_id, voter_id)
		VALUES ($1::uuid, $2::uuid)`,
		proposalID, voterNodeID,
	); err != nil {
		return false, fmt.Errorf("insert vote: %w", err)
	}

	// Atomically increment and check threshold.
	var newVotes int
	if err = r.db.QueryRow(ctx, `
		UPDATE revocation_proposals SET votes = votes + 1
		WHERE id = $1::uuid RETURNING votes`,
		proposalID,
	).Scan(&newVotes); err != nil {
		return false, fmt.Errorf("increment vote count: %w", err)
	}

	if newVotes < p.RequiredVotes {
		return false, nil // not yet
	}

	// Threshold met — execute.
	if err = r.executeRevocation(ctx, &p, voterNodeID, netCfg); err != nil {
		return false, fmt.Errorf("execute revocation: %w", err)
	}
	return true, nil
}

// executeRevocation carries out the actual suspend/ban/reinstate once the
// threshold has been met. Writes the ledger entry, updates DB state,
// and priority-gossips the result.
func (r *Revocation) executeRevocation(
	ctx context.Context,
	p *RevocationProposal,
	finalActorID string,
	netCfg NetworkConfig,
) error {
	pubKey, err := r.pubKeyForNode(ctx, p.SubjectID)
	if err != nil {
		return err
	}

	ledgerAction := "revoke"
	if p.Action == "reinstate" {
		ledgerAction = "reinstate"
	}

	payload, err := json.Marshal(map[string]any{
		"action":             ledgerAction,
		"type":               p.Action,
		"subject_pubkey":     pubKey,
		"reason":             p.Reason,
		"cascade_policy":     "soft",
		"grace_period_hours": netCfg.GracePeriodHours,
		"actor_id":           finalActorID,
		"proposal_id":        p.ID,
		"effective_at":       time.Now().UTC().Format(time.RFC3339),
		"priority":           p.Action != "reinstate",
	})
	if err != nil {
		return err
	}

	isPriority := p.Action != "reinstate"
	entry, err := r.ledger.Append(ctx, ledgerAction, &p.SubjectID, &finalActorID, payload, isPriority)
	if err != nil {
		return fmt.Errorf("append ledger entry: %w", err)
	}

	switch p.Action {
	case "suspend":
		// Set suspended_until if a duration was specified, otherwise NULL (indefinite).
		var suspendedUntil *time.Time
		if p.SuspendDurationHours > 0 {
			t := time.Now().UTC().Add(time.Duration(p.SuspendDurationHours) * time.Hour)
			suspendedUntil = &t
		}
		if _, err := r.db.Exec(ctx,
			`UPDATE nodes SET status = 'suspended', suspended_until = $2 WHERE id = $1`,
			p.SubjectID, suspendedUntil,
		); err != nil {
			return fmt.Errorf("update node status (suspend): %w", err)
		}
		// NOTE: suspended nodes still serve AXFR — only their voting rights are removed.
		// DO NOT set peers.trust_status='banned' here (that would block AXFR per design doc).
		if err := r.cascadeOrphan(ctx, p.SubjectID, entry.Seq, netCfg.GracePeriodHours); err != nil {
			return fmt.Errorf("cascade orphan: %w", err)
		}

	case "ban":
		if _, err := r.db.Exec(ctx,
			`UPDATE nodes SET status = 'banned' WHERE id = $1`, p.SubjectID,
		); err != nil {
			return fmt.Errorf("update node status (ban): %w", err)
		}
		_, _ = r.db.Exec(ctx,
			`UPDATE peers SET trust_status = 'banned' WHERE public_key = $1`, pubKey)
		if _, err := r.db.Exec(ctx, `
			INSERT INTO revoked_keys (public_key, revoked_at, reason, ledger_seq)
			VALUES ($1, now(), $2, $3) ON CONFLICT (public_key) DO NOTHING`,
			pubKey, p.Reason, entry.Seq,
		); err != nil {
			return fmt.Errorf("insert revoked key: %w", err)
		}
		if err := r.cascadeOrphan(ctx, p.SubjectID, entry.Seq, netCfg.GracePeriodHours); err != nil {
			return fmt.Errorf("cascade orphan (ban): %w", err)
		}

	case "reinstate":
		if _, err := r.db.Exec(ctx,
			`UPDATE nodes SET status = 'active', suspended_until = NULL WHERE id = $1`, p.SubjectID,
		); err != nil {
			return fmt.Errorf("update node status (reinstate): %w", err)
		}
		// Restore peer trust_status only if it was banned (from a prior BAN that was later reinstated,
		// which shouldn't normally happen, but defensive cleanup).
		_, _ = r.db.Exec(ctx,
			`UPDATE peers SET trust_status = 'trusted' WHERE public_key = $1 AND trust_status = 'banned'`, pubKey)
		if _, err := r.db.Exec(ctx, `
			UPDATE nodes SET status = 'active'
			WHERE id IN (
			    SELECT node_id FROM orphaned_nodes
			    WHERE cause_seq IN (
			        SELECT seq FROM trust_ledger
			        WHERE action = 'revoke' AND subject_id = $1::uuid
			    ) AND adopted_at IS NULL AND grace_until > now()
			)`, p.SubjectID,
		); err != nil {
			return fmt.Errorf("reinstate dependents: %w", err)
		}
	}

	// Mark proposal as executed.
	if _, err := r.db.Exec(ctx, `
		UPDATE revocation_proposals
		SET status = 'executed', executed_at = now(), ledger_seq = $1
		WHERE id = $2::uuid`,
		entry.Seq, p.ID,
	); err != nil {
		return fmt.Errorf("mark proposal executed: %w", err)
	}

	go r.gossip.PushPriorityEntry(ctx, *entry)
	return nil
}

// thresholdForAction returns the genesis-configured threshold for an action.
func (r *Revocation) thresholdForAction(action string, netCfg NetworkConfig) int {
	switch action {
	case "suspend":
		return netCfg.ThresholdSuspend
	case "ban":
		return netCfg.ThresholdBan
	case "reinstate":
		return netCfg.ThresholdReinstate
	case "role_upgrade":
		return netCfg.ThresholdRoleUpgrade
	default:
		return 2
	}
}

// cascadeOrphan marks nodes vouched exclusively by the revoked node as orphaned.
func (r *Revocation) cascadeOrphan(ctx context.Context, revokedNodeID string, causeSeq int64, gracePeriodHours int) error {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT n.id
		FROM nodes n
		JOIN trust_ledger tl ON tl.subject_id = n.id AND tl.action = 'vouch' AND tl.actor_id = $1::uuid
		WHERE n.status = 'active'
		  AND NOT EXISTS (
		      SELECT 1 FROM trust_ledger tl2
		      WHERE tl2.subject_id = n.id
		        AND tl2.action = 'vouch'
		        AND tl2.actor_id != $1::uuid
		        AND EXISTS (SELECT 1 FROM nodes v WHERE v.id = tl2.actor_id AND v.status = 'active')
		  )`,
		revokedNodeID,
	)
	if err != nil {
		return fmt.Errorf("query orphan candidates: %w", err)
	}
	defer rows.Close()

	graceUntil := time.Now().UTC().Add(time.Duration(gracePeriodHours) * time.Hour)
	for rows.Next() {
		var depID string
		if err := rows.Scan(&depID); err != nil {
			return err
		}
		if _, err := r.db.Exec(ctx,
			`UPDATE nodes SET status = 'orphaned' WHERE id = $1`, depID,
		); err != nil {
			return fmt.Errorf("update orphaned node %s: %w", depID, err)
		}
		if _, err := r.db.Exec(ctx, `
			INSERT INTO orphaned_nodes (node_id, orphaned_at, grace_until, cause_seq)
			VALUES ($1::uuid, now(), $2, $3) ON CONFLICT DO NOTHING`,
			depID, graceUntil, causeSeq,
		); err != nil {
			return fmt.Errorf("insert orphaned_nodes for %s: %w", depID, err)
		}
	}
	return rows.Err()
}

// ProcessExpiredGracePeriods converts orphaned nodes past their grace window
// to suspended.  Call periodically (e.g. hourly).
func (r *Revocation) ProcessExpiredGracePeriods(ctx context.Context) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE nodes SET status = 'suspended'
		WHERE status = 'orphaned'
		  AND id IN (
		      SELECT node_id FROM orphaned_nodes
		      WHERE grace_until < now() AND adopted_at IS NULL
		  )`)
	if err != nil {
		return 0, fmt.Errorf("expire orphan grace periods: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ProcessExpiredSuspensions reinstates nodes whose temporary suspension has
// passed its suspended_until deadline. Call periodically (e.g. hourly).
func (r *Revocation) ProcessExpiredSuspensions(ctx context.Context) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE nodes
		SET status = 'active', suspended_until = NULL
		WHERE status = 'suspended'
		  AND suspended_until IS NOT NULL
		  AND suspended_until < now()`)
	if err != nil {
		return 0, fmt.Errorf("process expired suspensions: %w", err)
	}
	n := tag.RowsAffected()
	if n > 0 {
		// Also restore peer trust status for auto-reinstated nodes.
		_, _ = r.db.Exec(ctx, `
			UPDATE peers p
			SET trust_status = 'trusted'
			FROM nodes n
			WHERE n.public_key = p.public_key
			  AND n.status = 'active'
			  AND p.trust_status = 'banned'`)
	}
	return n, nil
}

// ExpireRevocationProposals marks open proposals that have passed expiry as
// expired.  Call periodically (e.g. hourly).
func (r *Revocation) ExpireRevocationProposals(ctx context.Context) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE revocation_proposals SET status = 'expired'
		WHERE status = 'voting' AND expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("expire revocation proposals: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ExpireGenesisRevocationProposals marks open genesis-revocation proposals that
// have passed expiry.  Call periodically (e.g. hourly).
func (r *Revocation) ExpireGenesisRevocationProposals(ctx context.Context) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE revocation_genesis_proposals SET status = 'expired'
		WHERE status = 'voting' AND expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("expire genesis revocation proposals: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RetractVouch allows the original voucher to withdraw their vouch for a node
// (Tier 3 revocation per design doc).
//
// Effect:
//   - If the subject has no other active vouchers → subject becomes "orphaned"
//     with the standard grace period (may be adopted by another trusted node).
//   - If other active vouchers exist → nothing changes for the subject's status;
//     only the trust score is reduced (recorded in ledger).
//
// This does NOT execute a SUSPEND or BAN directly — it only reduces trust.
func (r *Revocation) RetractVouch(ctx context.Context, subjectNodeID, revokerNodeID string, netCfg NetworkConfig) error {
	// Verify revoker did actually vouch for the subject.
	var vouchCount int
	if err := r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM trust_ledger
		WHERE action = 'vouch' AND subject_id = $1::uuid AND actor_id = $2::uuid`,
		subjectNodeID, revokerNodeID,
	).Scan(&vouchCount); err != nil {
		return fmt.Errorf("check vouch history: %w", err)
	}
	if vouchCount == 0 {
		return fmt.Errorf("node %s never vouched for node %s", revokerNodeID, subjectNodeID)
	}

	pubKey, err := r.pubKeyForNode(ctx, subjectNodeID)
	if err != nil {
		return err
	}

	// Check if subject has other active vouchers besides revokerNodeID.
	var otherVouchers int
	if err := r.db.QueryRow(ctx, `
		SELECT COUNT(DISTINCT tl.actor_id)
		FROM trust_ledger tl
		JOIN nodes v ON v.id = tl.actor_id AND v.status = 'active'
		WHERE tl.action = 'vouch'
		  AND tl.subject_id = $1::uuid
		  AND tl.actor_id != $2::uuid`,
		subjectNodeID, revokerNodeID,
	).Scan(&otherVouchers); err != nil {
		return fmt.Errorf("check other vouchers: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"action":         "retract_vouch",
		"subject_pubkey": pubKey,
		"revoker_id":     revokerNodeID,
		"orphaned":       otherVouchers == 0,
	})
	if err != nil {
		return err
	}

	entry, err := r.ledger.Append(ctx, "vouch", &subjectNodeID, &revokerNodeID, payload, false)
	if err != nil {
		return fmt.Errorf("append retract_vouch entry: %w", err)
	}

	if otherVouchers == 0 {
		// Last voucher withdrawn — mark subject as orphaned with grace period.
		var subjectStatus string
		_ = r.db.QueryRow(ctx,
			`SELECT status FROM nodes WHERE id = $1`, subjectNodeID,
		).Scan(&subjectStatus)

		if subjectStatus == "active" {
			if _, err := r.db.Exec(ctx,
				`UPDATE nodes SET status = 'orphaned' WHERE id = $1`, subjectNodeID,
			); err != nil {
				return fmt.Errorf("update orphaned status: %w", err)
			}
			graceUntil := time.Now().UTC().Add(time.Duration(netCfg.GracePeriodHours) * time.Hour)
			if _, err := r.db.Exec(ctx, `
				INSERT INTO orphaned_nodes (node_id, orphaned_at, grace_until, cause_seq)
				VALUES ($1::uuid, now(), $2, $3) ON CONFLICT DO NOTHING`,
				subjectNodeID, graceUntil, entry.Seq,
			); err != nil {
				return fmt.Errorf("insert orphaned_nodes: %w", err)
			}
		}
	}

	return nil
}

// AdoptOrphan re-vouches an orphaned node by any single trusted node (no threshold).
func (r *Revocation) AdoptOrphan(ctx context.Context, orphanNodeID, adopterNodeID string) error {
	pubKey, err := r.pubKeyForNode(ctx, orphanNodeID)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"action":         "vouch",
		"subject_pubkey": pubKey,
		"adopter_id":     adopterNodeID,
		"adoption":       true,
	})
	if err != nil {
		return err
	}
	if _, err := r.ledger.Append(ctx, "vouch", &orphanNodeID, &adopterNodeID, payload, false); err != nil {
		return fmt.Errorf("append adoption vouch: %w", err)
	}
	if _, err := r.db.Exec(ctx,
		`UPDATE nodes SET status = 'active' WHERE id = $1 AND status = 'orphaned'`, orphanNodeID,
	); err != nil {
		return fmt.Errorf("update adopted node status: %w", err)
	}
	if _, err := r.db.Exec(ctx, `
		UPDATE orphaned_nodes SET adopted_by = $1::uuid, adopted_at = now()
		WHERE node_id = $2::uuid AND adopted_at IS NULL`,
		adopterNodeID, orphanNodeID,
	); err != nil {
		return fmt.Errorf("update orphaned_nodes record: %w", err)
	}
	return nil
}

// pubKeyForNode fetches the public key for a node by its UUID.
func (r *Revocation) pubKeyForNode(ctx context.Context, nodeID string) (string, error) {
	var pubKey string
	if err := r.db.QueryRow(ctx,
		`SELECT public_key FROM nodes WHERE id = $1`, nodeID,
	).Scan(&pubKey); err != nil {
		return "", fmt.Errorf("node %s not found: %w", nodeID, err)
	}
	return pubKey, nil
}

// ProposeRevokeGenesis opens or votes on a "revoke_genesis" proposal.
// Threshold: 67% of total active trusted nodes (supermajority per design doc).
// Effect when executed: genesis node's role is downgraded to 'master' — loses
// unilateral power but trust chain remains valid.
func (r *Revocation) ProposeRevokeGenesis(
	ctx context.Context,
	actorNodeID string,
	reason string,
) (proposalID string, executed bool, err error) {
	// Only non-genesis active nodes can propose.
	var actorRole string
	if err = r.db.QueryRow(ctx,
		`SELECT role FROM nodes WHERE id = $1`, actorNodeID,
	).Scan(&actorRole); err != nil {
		return "", false, fmt.Errorf("actor node not found: %w", err)
	}
	if actorRole == "genesis" {
		return "", false, fmt.Errorf("genesis node cannot propose its own revocation")
	}

	// Resolve genesis node ID.
	var genesisNodeID string
	if err = r.db.QueryRow(ctx,
		`SELECT id FROM nodes WHERE role = 'genesis' LIMIT 1`,
	).Scan(&genesisNodeID); err != nil {
		return "", false, fmt.Errorf("genesis node not found: %w", err)
	}

	// Calculate 67% supermajority threshold from active trusted nodes.
	var activeCount int
	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM nodes WHERE status = 'active'`,
	).Scan(&activeCount)
	requiredVotes := supermajorityThreshold(activeCount) // ceil(activeCount * 0.67)
	if requiredVotes < 1 {
		requiredVotes = 1
	}

	// Check for existing open proposal.
	var existingID string
	lookupErr := r.db.QueryRow(ctx, `
		SELECT id FROM revocation_genesis_proposals
		WHERE status = 'voting'`).Scan(&existingID)
	if lookupErr == nil {
		// Proposal already open — add this vote.
		return existingID, false, r.addRevokeGenesisVote(ctx, existingID, actorNodeID, genesisNodeID, requiredVotes, reason)
	}
	if !errors.Is(lookupErr, pgx.ErrNoRows) {
		return "", false, fmt.Errorf("check existing genesis revocation proposal: %w", lookupErr)
	}

	// Create new proposal.
	id, err := newUUID()
	if err != nil {
		return "", false, fmt.Errorf("generate proposal id: %w", err)
	}
	expires := time.Now().UTC().Add(7 * 24 * time.Hour) // 7-day window for supermajority
	if _, err = r.db.Exec(ctx, `
		INSERT INTO revocation_genesis_proposals
		    (id, reason, required_votes, expires_at)
		VALUES ($1::uuid, $2, $3, $4)`,
		id, reason, requiredVotes, expires,
	); err != nil {
		return "", false, fmt.Errorf("insert revoke_genesis proposal: %w", err)
	}

	if err = r.addRevokeGenesisVote(ctx, id, actorNodeID, genesisNodeID, requiredVotes, reason); err != nil {
		return id, false, err
	}

	// Re-check if executed (threshold=1 edge case in tiny network).
	var status string
	_ = r.db.QueryRow(ctx,
		`SELECT status FROM revocation_genesis_proposals WHERE id = $1::uuid`, id,
	).Scan(&status)
	return id, status == "executed", nil
}

// addRevokeGenesisVote records one vote; executes when supermajority is met.
func (r *Revocation) addRevokeGenesisVote(
	ctx context.Context,
	proposalID, voterNodeID, genesisNodeID string,
	requiredVotes int,
	reason string,
) error {
	// Prevent double-vote.
	var alreadyVoted bool
	_ = r.db.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM revocation_genesis_votes
		WHERE proposal_id = $1::uuid AND voter_id = $2::uuid)`,
		proposalID, voterNodeID,
	).Scan(&alreadyVoted)
	if alreadyVoted {
		return fmt.Errorf("node %s has already voted on genesis revocation", voterNodeID)
	}

	if _, err := r.db.Exec(ctx, `
		INSERT INTO revocation_genesis_votes (proposal_id, voter_id)
		VALUES ($1::uuid, $2::uuid)`,
		proposalID, voterNodeID,
	); err != nil {
		return fmt.Errorf("insert genesis revocation vote: %w", err)
	}

	var newVotes int
	if err := r.db.QueryRow(ctx, `
		UPDATE revocation_genesis_proposals SET votes = votes + 1
		WHERE id = $1::uuid RETURNING votes`,
		proposalID,
	).Scan(&newVotes); err != nil {
		return fmt.Errorf("increment genesis revocation vote count: %w", err)
	}

	if newVotes < requiredVotes {
		return nil
	}

	// Supermajority reached — downgrade genesis to 'master'.
	return r.executeRevokeGenesis(ctx, proposalID, genesisNodeID, voterNodeID, reason)
}

// executeRevokeGenesis downgrades the genesis node to 'master' role.
// Trust chain remains intact; only unilateral power is revoked.
func (r *Revocation) executeRevokeGenesis(
	ctx context.Context,
	proposalID, genesisNodeID, finalActorID, reason string,
) error {
	pubKey, err := r.pubKeyForNode(ctx, genesisNodeID)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(map[string]any{
		"action":         "revoke_genesis",
		"subject_pubkey": pubKey,
		"reason":         reason,
		"proposal_id":    proposalID,
		"effect":         "genesis downgraded to master; unilateral power revoked; trust chain preserved",
		"effective_at":   time.Now().UTC().Format(time.RFC3339),
		"priority":       true,
	})
	if err != nil {
		return err
	}

	entry, err := r.ledger.Append(ctx, "revoke_genesis", &genesisNodeID, &finalActorID, payload, true)
	if err != nil {
		return fmt.Errorf("append revoke_genesis ledger entry: %w", err)
	}

	// Downgrade role — no status change, node stays active.
	if _, err := r.db.Exec(ctx,
		`UPDATE nodes SET role = 'master' WHERE id = $1`, genesisNodeID,
	); err != nil {
		return fmt.Errorf("downgrade genesis role: %w", err)
	}

	if _, err := r.db.Exec(ctx, `
		UPDATE revocation_genesis_proposals
		SET status = 'executed', executed_at = now(), ledger_seq = $1
		WHERE id = $2::uuid`,
		entry.Seq, proposalID,
	); err != nil {
		return fmt.Errorf("mark genesis revocation proposal executed: %w", err)
	}

	go r.gossip.PushPriorityEntry(ctx, *entry)
	return nil
}

// supermajorityThreshold computes ceil(n * 0.67) — the 67% supermajority count.
func supermajorityThreshold(n int) int {
	if n == 0 {
		return 1
	}
	// ceil(n * 67 / 100)
	return (n*67 + 99) / 100
}

// ProposeRoleUpgrade opens or joins a role-upgrade proposal to promote a slave
// node to master. Requires threshold_role_upgrade votes (default: 3).
//
// Effect when executed:
//   - nodes.role updated from 'slave' to 'master'
//   - Ledger entry with action='role_upgrade' is appended
//
// Returns proposalID and whether the upgrade was executed immediately.
func (r *Revocation) ProposeRoleUpgrade(
	ctx context.Context,
	subjectNodeID, actorNodeID, reason string,
	netCfg NetworkConfig,
) (proposalID string, executed bool, err error) {
	// Subject must be a slave node with active status.
	var subjectRole, subjectStatus string
	if err = r.db.QueryRow(ctx,
		`SELECT role, status FROM nodes WHERE id = $1`, subjectNodeID,
	).Scan(&subjectRole, &subjectStatus); err != nil {
		return "", false, fmt.Errorf("subject node not found: %w", err)
	}
	if subjectRole != "slave" {
		return "", false, fmt.Errorf("role upgrade only applies to slave nodes (current role: %s)", subjectRole)
	}
	if subjectStatus != "active" {
		return "", false, fmt.Errorf("node must be active for role upgrade (current status: %s)", subjectStatus)
	}

	// Actor must be active.
	var actorStatus string
	if err = r.db.QueryRow(ctx,
		`SELECT status FROM nodes WHERE id = $1`, actorNodeID,
	).Scan(&actorStatus); err != nil {
		return "", false, fmt.Errorf("actor node not found: %w", err)
	}
	if actorStatus != "active" {
		return "", false, fmt.Errorf("actor node is not active (status: %s)", actorStatus)
	}

	requiredVotes := netCfg.ThresholdRoleUpgrade
	if requiredVotes < 1 {
		requiredVotes = 1
	}

	// Check for open proposal for the same subject.
	var existingID string
	lookupErr := r.db.QueryRow(ctx, `
		SELECT id FROM role_upgrade_proposals
		WHERE subject_id = $1::uuid AND status = 'voting'`, subjectNodeID,
	).Scan(&existingID)
	if lookupErr == nil {
		// Existing open proposal — add vote.
		err = r.addRoleUpgradeVote(ctx, existingID, actorNodeID, subjectNodeID, requiredVotes, reason)
		if err != nil {
			return existingID, false, err
		}
		// Check whether it just executed.
		var status string
		_ = r.db.QueryRow(ctx,
			`SELECT status FROM role_upgrade_proposals WHERE id = $1::uuid`, existingID,
		).Scan(&status)
		return existingID, status == "executed", nil
	}
	if !errors.Is(lookupErr, pgx.ErrNoRows) {
		return "", false, fmt.Errorf("check existing role upgrade proposal: %w", lookupErr)
	}

	// Create new proposal.
	id, err := newUUID()
	if err != nil {
		return "", false, fmt.Errorf("generate proposal id: %w", err)
	}
	expires := time.Now().UTC().Add(72 * time.Hour)
	if _, err = r.db.Exec(ctx, `
		INSERT INTO role_upgrade_proposals (id, subject_id, reason, required_votes, expires_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5)`,
		id, subjectNodeID, reason, requiredVotes, expires,
	); err != nil {
		return "", false, fmt.Errorf("insert role upgrade proposal: %w", err)
	}

	if err = r.addRoleUpgradeVote(ctx, id, actorNodeID, subjectNodeID, requiredVotes, reason); err != nil {
		return id, false, err
	}

	var status string
	_ = r.db.QueryRow(ctx,
		`SELECT status FROM role_upgrade_proposals WHERE id = $1::uuid`, id,
	).Scan(&status)
	return id, status == "executed", nil
}

// addRoleUpgradeVote records one vote; executes when threshold is met.
func (r *Revocation) addRoleUpgradeVote(
	ctx context.Context,
	proposalID, voterNodeID, subjectNodeID string,
	requiredVotes int,
	reason string,
) error {
	// Prevent double-vote.
	var alreadyVoted bool
	_ = r.db.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM role_upgrade_votes
		WHERE proposal_id = $1::uuid AND voter_id = $2::uuid)`,
		proposalID, voterNodeID,
	).Scan(&alreadyVoted)
	if alreadyVoted {
		return fmt.Errorf("node %s has already voted on this role upgrade proposal", voterNodeID)
	}

	if _, err := r.db.Exec(ctx, `
		INSERT INTO role_upgrade_votes (proposal_id, voter_id)
		VALUES ($1::uuid, $2::uuid)`,
		proposalID, voterNodeID,
	); err != nil {
		return fmt.Errorf("insert role upgrade vote: %w", err)
	}

	var newVotes int
	if err := r.db.QueryRow(ctx, `
		UPDATE role_upgrade_proposals SET votes = votes + 1
		WHERE id = $1::uuid RETURNING votes`,
		proposalID,
	).Scan(&newVotes); err != nil {
		return fmt.Errorf("increment role upgrade vote count: %w", err)
	}

	if newVotes < requiredVotes {
		return nil
	}

	return r.executeRoleUpgrade(ctx, proposalID, subjectNodeID, voterNodeID, reason)
}

// executeRoleUpgrade promotes the node from slave to master and appends the
// ledger entry.
func (r *Revocation) executeRoleUpgrade(
	ctx context.Context,
	proposalID, subjectNodeID, finalActorID, reason string,
) error {
	pubKey, err := r.pubKeyForNode(ctx, subjectNodeID)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(map[string]any{
		"action":         "role_upgrade",
		"subject_pubkey": pubKey,
		"reason":         reason,
		"proposal_id":    proposalID,
		"new_role":       "master",
		"effective_at":   time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}

	entry, err := r.ledger.Append(ctx, "role_upgrade", &subjectNodeID, &finalActorID, payload, false)
	if err != nil {
		return fmt.Errorf("append role_upgrade ledger entry: %w", err)
	}

	if _, err := r.db.Exec(ctx,
		`UPDATE nodes SET role = 'master' WHERE id = $1`, subjectNodeID,
	); err != nil {
		return fmt.Errorf("update node role: %w", err)
	}

	if _, err := r.db.Exec(ctx, `
		UPDATE role_upgrade_proposals
		SET status = 'executed', executed_at = now(), ledger_seq = $1
		WHERE id = $2::uuid`,
		entry.Seq, proposalID,
	); err != nil {
		return fmt.Errorf("mark role upgrade proposal executed: %w", err)
	}

	go r.gossip.PushPriorityEntry(ctx, *entry)
	return nil
}

// ExpireRoleUpgradeProposals marks open role-upgrade proposals past their
// expiry date as expired. Call periodically (e.g. hourly).
func (r *Revocation) ExpireRoleUpgradeProposals(ctx context.Context) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE role_upgrade_proposals SET status = 'expired'
		WHERE status = 'voting' AND expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("expire role upgrade proposals: %w", err)
	}
	return tag.RowsAffected(), nil
}
