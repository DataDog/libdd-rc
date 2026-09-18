package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	remotequeriesv1alpha1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_queries"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The fully-qualified Magic Tunnel method URIs for the Remote Queries team's
// experimental v1alpha1 control service. Handlers are registered under these
// names, and payloads are dispatched to them by the Magic Tunnel based on the
// URI each request carries.
const (
	remoteQueriesResolveTargetURI = "rc.x509.magic_tunnel.remote_queries.v1alpha1.RemoteQueriesControlService/ResolveTarget"
	remoteQueriesStartRunURI      = "rc.x509.magic_tunnel.remote_queries.v1alpha1.RemoteQueriesControlService/StartRun"
	remoteQueriesGetRunStatusURI  = "rc.x509.magic_tunnel.remote_queries.v1alpha1.RemoteQueriesControlService/GetRunStatus"
	remoteQueriesCancelRunURI     = "rc.x509.magic_tunnel.remote_queries.v1alpha1.RemoteQueriesControlService/CancelRun"
)

// Stable, machine-readable error codes carried by ControlError fields of
// control responses. This vocabulary is closed: callers match on these codes
// and never parse the human-readable message.
const (
	remoteQueriesErrMissingReason         = "MISSING_REASON"
	remoteQueriesErrInvalidIdentity       = "INVALID_IDENTITY"
	remoteQueriesErrInvalidIntegration    = "INVALID_INTEGRATION"
	remoteQueriesErrInvalidTarget         = "INVALID_TARGET"
	remoteQueriesErrInvalidQuery          = "INVALID_QUERY"
	remoteQueriesErrInvalidResultDelivery = "INVALID_RESULT_DELIVERY"
	remoteQueriesErrCommandConflict       = "COMMAND_CONFLICT"
)

// remoteQueriesController is a deterministic, concurrency-safe, in-memory
// reference implementation of the Remote Queries control lifecycle for the
// testx509 Magic Tunnel host.
//
// It simulates the control-plane state machine ONLY:
//
//   - it executes no SQL: a resolved or started run never touches a database;
//   - it performs no upload: no result page is ever produced or uploaded;
//   - it inspects no actual Agent configuration: ResolveTarget deterministically
//     reports a match for every structurally valid target;
//   - it keeps every run entry exclusively in process memory, so ALL state is
//     lost when the process restarts: after a restart, a previously accepted
//     run is indistinguishable from one that never started (callers observe
//     NOT_FOUND), and a retried StartRun for the same identity starts a fresh
//     entry.
//
// The controller's mutable state is instance-owned so tests can drive isolated
// copies; main wires exactly one explicit instance into the registered
// handlers.
//
// Semantics implemented:
//
//   - ResolveTarget validates the request and returns MATCHED for every valid
//     target. TARGET_NOT_FOUND and AMBIGUOUS_TARGET are real-resolver outcomes
//     and are never produced by this simulation.
//   - StartRun keys admitted runs by the full (org_id, task_id, run_id,
//     upload_id) identity. The first valid start stores ACCEPTED and returns
//     ACCEPTED. A duplicate with the same identity and the same canonical
//     command returns ALREADY_ACCEPTED with the original acceptance time. A
//     duplicate with a different canonical command fails closed with REJECTED
//     and the COMMAND_CONFLICT code.
//   - GetRunStatus returns NOT_FOUND or the stored lifecycle state. It never
//     fabricates completion, receipts, diagnostics, or terminal errors.
//   - CancelRun is idempotent. Because this simulation has no work to stop,
//     an accepted entry transitions directly to CANCELLED; see
//     handleCancelRun for why a real executor must keep "cancellation
//     requested" and "cleanup complete" distinct.
type remoteQueriesController struct {
	// mu guards runs and every runEntry it contains.
	mu sync.Mutex

	// runs maps the full (org_id, task_id, run_id, upload_id) identity tuple
	// to its admitted entry.
	runs map[remoteQueriesRunKey]*remoteQueriesRunEntry

	// now reports the controller's notion of the current time. It is a field
	// so tests can drive deterministic timestamps; production code uses
	// time.Now.
	now func() time.Time
}

// remoteQueriesRunKey is the immutable run identity tuple that keys the
// controller's admitted runs.
type remoteQueriesRunKey struct {
	orgID    uint64
	taskID   string
	runID    string
	uploadID string
}

// remoteQueriesRunEntry is one admitted run in the controller's memory.
type remoteQueriesRunEntry struct {
	// commandDigest is the canonical digest of the accepted command's
	// execution semantics; see canonicalCommandDigest.
	commandDigest string

	// state is the stored lifecycle state. This simulation only ever stores
	// ACCEPTED and CANCELLED: with no execution, no upload, and no failure
	// injection, no other state is reachable, and none are ever fabricated.
	state remotequeriesv1alpha1.RunState

	// acceptedAt is when the run was first admitted.
	acceptedAt time.Time

	// updatedAt is when state last transitioned.
	updatedAt time.Time
}

// newRemoteQueriesController returns a ready-to-use controller.
func newRemoteQueriesController() *remoteQueriesController {
	return &remoteQueriesController{
		runs: make(map[remoteQueriesRunKey]*remoteQueriesRunEntry),
		now:  time.Now,
	}
}

// decodeRemoteQueriesRequest decodes a Magic Tunnel request payload into dst.
//
// Malformed protobuf is returned as an error rather than a rejected response:
// the MagicTunnelResponse envelope carries handler errors separately from
// structured application payloads, and an undecodable request has no
// method state to reject with. proto.Unmarshal never panics on malformed
// input, so neither do the handlers.
func decodeRemoteQueriesRequest(method string, payload []byte, dst proto.Message) error {
	if err := proto.Unmarshal(payload, dst); err != nil {
		return fmt.Errorf("%s: malformed request payload: %w", method, err)
	}
	return nil
}

// remoteQueriesControlError is a bounded, structured control-plane error
// carried in a ControlError message of a control response.
type remoteQueriesControlError struct {
	code    string
	message string
}

// proto renders the error as the contract's ControlError message.
func (e *remoteQueriesControlError) proto() *remotequeriesv1alpha1.ControlError {
	return &remotequeriesv1alpha1.ControlError{
		Code:    e.code,
		Message: e.message,
	}
}

// handleResolveTarget implements the HandlerFunc signature for the
// RemoteQueriesControlService/ResolveTarget URI.
//
// The reference state machine does not inspect any actual Agent or database
// configuration: every structurally valid request deterministically resolves
// to MATCHED, which proves request decoding and target validation but does
// not imply inspection of real configuration.
func (c *remoteQueriesController) handleResolveTarget(correlationID uint64, payload []byte) ([]byte, error) {
	var req remotequeriesv1alpha1.ResolveTargetRequest
	if err := decodeRemoteQueriesRequest("RemoteQueriesControlService/ResolveTarget", payload, &req); err != nil {
		return nil, err
	}

	log.Printf("remote queries resolve target (correlation_id=%d) from connection %q: reason=%q integration=%q",
		correlationID, req.GetConnectionId(), req.GetReason(), req.GetIntegration())

	resp := &remotequeriesv1alpha1.ResolveTargetResponse{}
	switch {
	case remoteQueriesReasonMissing(req.GetReason()):
		resp.Status = remotequeriesv1alpha1.ResolveTargetStatus_RESOLVE_TARGET_STATUS_RESOLUTION_ERROR
		resp.Error = &remotequeriesv1alpha1.ControlError{
			Code:    remoteQueriesErrMissingReason,
			Message: "reason must be a non-empty audit string",
		}
	case req.GetIntegration() == "":
		resp.Status = remotequeriesv1alpha1.ResolveTargetStatus_RESOLVE_TARGET_STATUS_RESOLUTION_ERROR
		resp.Error = &remotequeriesv1alpha1.ControlError{
			Code:    remoteQueriesErrInvalidIntegration,
			Message: "integration must be a non-empty identifier",
		}
	default:
		if err := remoteQueriesValidateTarget(req.GetTarget()); err != nil {
			resp.Status = remotequeriesv1alpha1.ResolveTargetStatus_RESOLVE_TARGET_STATUS_RESOLUTION_ERROR
			resp.Error = err.proto()
		} else {
			// Deterministic simulated match for every valid target.
			resp.Status = remotequeriesv1alpha1.ResolveTargetStatus_RESOLVE_TARGET_STATUS_MATCHED
		}
	}

	return proto.Marshal(resp)
}

// handleStartRun implements the HandlerFunc signature for the
// RemoteQueriesControlService/StartRun URI.
//
// The first valid start for an identity stores ACCEPTED and returns
// ACCEPTED. The same identity with the same canonical command returns
// ALREADY_ACCEPTED with the original acceptance time, whether or not the
// run has since transitioned to another state: the existing admission stays
// authoritative. The same identity with a different canonical command fails
// closed with REJECTED and the COMMAND_CONFLICT code. Invalid requests are
// rejected with the per-field error code instead.
func (c *remoteQueriesController) handleStartRun(correlationID uint64, payload []byte) ([]byte, error) {
	var req remotequeriesv1alpha1.StartRunRequest
	if err := decodeRemoteQueriesRequest("RemoteQueriesControlService/StartRun", payload, &req); err != nil {
		return nil, err
	}

	log.Printf("remote queries start run (correlation_id=%d) from connection %q: reason=%q org_id=%d task_id=%q run_id=%q upload_id=%q",
		correlationID, req.GetConnectionId(), req.GetReason(),
		req.GetRunIdentity().GetOrgId(), req.GetRunIdentity().GetTaskId(),
		req.GetRunIdentity().GetRunId(), req.GetRunIdentity().GetUploadId())

	resp := &remotequeriesv1alpha1.StartRunResponse{
		RunIdentity: req.GetRunIdentity(),
	}

	if validationErr := remoteQueriesValidateStartRun(&req); validationErr != nil {
		resp.Status = remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED
		resp.Error = validationErr.proto()
		return proto.Marshal(resp)
	}

	// The digest covers execution semantics only, so it is computed outside
	// the lock and compared under it.
	digest := canonicalCommandDigest(&req)
	key := remoteQueriesRunKeyFromIdentity(req.GetRunIdentity())

	c.mu.Lock()
	defer c.mu.Unlock()

	existing, ok := c.runs[key]
	switch {
	case !ok:
		acceptedAt := c.now()
		c.runs[key] = &remoteQueriesRunEntry{
			commandDigest: digest,
			state:         remotequeriesv1alpha1.RunState_RUN_STATE_ACCEPTED,
			acceptedAt:    acceptedAt,
			updatedAt:     acceptedAt,
		}
		resp.Status = remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_ACCEPTED
		resp.AcceptedAt = timestamppb.New(acceptedAt)
	case existing.commandDigest == digest:
		// A duplicate delivery of the accepted command reports the existing
		// admission, including its original acceptance time. The command is
		// never executed twice.
		resp.Status = remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_ALREADY_ACCEPTED
		resp.AcceptedAt = timestamppb.New(existing.acceptedAt)
	default:
		// The same identity was already accepted for a different command:
		// fail closed rather than mutate or re-execute.
		resp.Status = remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED
		resp.Error = &remotequeriesv1alpha1.ControlError{
			Code:    remoteQueriesErrCommandConflict,
			Message: "a run with this identity was already accepted with a different command",
		}
	}

	return proto.Marshal(resp)
}

// handleGetRunStatus implements the HandlerFunc signature for the
// RemoteQueriesControlService/GetRunStatus URI.
//
// It returns NOT_FOUND when no run with the requested identity was ever
// accepted by this process, or the stored lifecycle state otherwise. It never
// fabricates completion, receipts, diagnostics, or terminal errors: this
// simulation stores only what its own transitions produced, and the only
// states it ever stores are ACCEPTED and CANCELLED.
//
// Structurally invalid lookups are returned as errors rather than responses:
// the RunState enum is a pure state enum with no rejected value, so there is
// no structured state to reject with.
func (c *remoteQueriesController) handleGetRunStatus(correlationID uint64, payload []byte) ([]byte, error) {
	var req remotequeriesv1alpha1.GetRunStatusRequest
	if err := decodeRemoteQueriesRequest("RemoteQueriesControlService/GetRunStatus", payload, &req); err != nil {
		return nil, err
	}

	log.Printf("remote queries get run status (correlation_id=%d) from connection %q: reason=%q org_id=%d task_id=%q run_id=%q upload_id=%q",
		correlationID, req.GetConnectionId(), req.GetReason(),
		req.GetRunIdentity().GetOrgId(), req.GetRunIdentity().GetTaskId(),
		req.GetRunIdentity().GetRunId(), req.GetRunIdentity().GetUploadId())

	if remoteQueriesReasonMissing(req.GetReason()) {
		return nil, fmt.Errorf("RemoteQueriesControlService/GetRunStatus: reason must be a non-empty audit string")
	}
	if err := remoteQueriesValidateIdentity(req.GetRunIdentity()); err != nil {
		return nil, fmt.Errorf("RemoteQueriesControlService/GetRunStatus: %s", err.message)
	}

	key := remoteQueriesRunKeyFromIdentity(req.GetRunIdentity())

	c.mu.Lock()
	defer c.mu.Unlock()

	resp := &remotequeriesv1alpha1.GetRunStatusResponse{
		RunIdentity: req.GetRunIdentity(),
	}
	entry, ok := c.runs[key]
	if !ok {
		resp.State = remotequeriesv1alpha1.RunState_RUN_STATE_NOT_FOUND
		return proto.Marshal(resp)
	}

	// Report only stored facts. This simulation has no execution, so it never
	// stores a terminal error, a receipt, or diagnostics, and none are
	// reported here.
	resp.State = entry.state
	resp.UpdatedAt = timestamppb.New(entry.updatedAt)

	return proto.Marshal(resp)
}

// handleCancelRun implements the HandlerFunc signature for the
// RemoteQueriesControlService/CancelRun URI.
//
// Cancellation is idempotent and addressed to the immutable run identity.
//
// This no-work simulation transitions an ACCEPTED entry directly to CANCELLED
// because there is no SQL execution or upload to stop, so cleanup is
// trivially complete. A REAL executor MUST distinguish cancellation
// requested from cleanup complete: it would respond CANCELLATION_REQUESTED,
// keep the entry in RUN_STATE_CANCELLATION_REQUESTED while work drains,
// return ALREADY_REQUESTED for repeats during that window, and only report
// CANCELLED after bounded cleanup finishes. ALREADY_REQUESTED is unreachable
// in this simulation precisely because its cancellation completes
// synchronously; it stays in the contract for real executors.
func (c *remoteQueriesController) handleCancelRun(correlationID uint64, payload []byte) ([]byte, error) {
	var req remotequeriesv1alpha1.CancelRunRequest
	if err := decodeRemoteQueriesRequest("RemoteQueriesControlService/CancelRun", payload, &req); err != nil {
		return nil, err
	}

	log.Printf("remote queries cancel run (correlation_id=%d) from connection %q: reason=%q org_id=%d task_id=%q run_id=%q upload_id=%q",
		correlationID, req.GetConnectionId(), req.GetReason(),
		req.GetRunIdentity().GetOrgId(), req.GetRunIdentity().GetTaskId(),
		req.GetRunIdentity().GetRunId(), req.GetRunIdentity().GetUploadId())

	resp := &remotequeriesv1alpha1.CancelRunResponse{
		RunIdentity: req.GetRunIdentity(),
	}

	if validationErr := remoteQueriesValidateCancel(&req); validationErr != nil {
		resp.Status = remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_REJECTED
		resp.Error = validationErr.proto()
		return proto.Marshal(resp)
	}

	key := remoteQueriesRunKeyFromIdentity(req.GetRunIdentity())

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.runs[key]
	if !ok {
		resp.Status = remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_NOT_FOUND
		return proto.Marshal(resp)
	}

	if entry.state == remotequeriesv1alpha1.RunState_RUN_STATE_ACCEPTED {
		// See the method comment: direct ACCEPTED -> CANCELLED transition is
		// only valid because this simulation has no work to clean up.
		entry.state = remotequeriesv1alpha1.RunState_RUN_STATE_CANCELLED
		entry.updatedAt = c.now()
		resp.Status = remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_CANCELLATION_REQUESTED
		resp.UpdatedAt = timestamppb.New(entry.updatedAt)
		log.Printf("remote queries cancel run (correlation_id=%d): reference simulation transitioned run org_id=%d run_id=%q directly to CANCELLED; a real executor distinguishes cancellation requested from cleanup complete",
			correlationID, key.orgID, key.runID)
		return proto.Marshal(resp)
	}

	// CANCELLED is the only terminal state this simulation can store, but
	// any terminal entry reports ALREADY_TERMINAL deterministically.
	resp.Status = remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_ALREADY_TERMINAL
	resp.UpdatedAt = timestamppb.New(entry.updatedAt)

	return proto.Marshal(resp)
}

// remoteQueriesReasonMissing reports whether the required audit reason is
// absent.
func remoteQueriesReasonMissing(reason string) bool {
	return strings.TrimSpace(reason) == ""
}

// remoteQueriesValidateStartRun validates a start request and returns the
// bounded rejection error, or nil when the request is valid.
func remoteQueriesValidateStartRun(req *remotequeriesv1alpha1.StartRunRequest) *remoteQueriesControlError {
	if remoteQueriesReasonMissing(req.GetReason()) {
		return &remoteQueriesControlError{
			code:    remoteQueriesErrMissingReason,
			message: "reason must be a non-empty audit string",
		}
	}
	if err := remoteQueriesValidateIdentity(req.GetRunIdentity()); err != nil {
		return err
	}
	if req.GetIntegration() == "" {
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidIntegration,
			message: "integration must be a non-empty identifier",
		}
	}
	if err := remoteQueriesValidateTarget(req.GetTarget()); err != nil {
		return err
	}
	if strings.TrimSpace(req.GetQuery()) == "" {
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidQuery,
			message: "query must be a non-empty string",
		}
	}
	return remoteQueriesValidateResultDelivery(req.GetResultDelivery())
}

// remoteQueriesValidateCancel validates a cancel request and returns the
// bounded rejection error, or nil when the request is valid.
func remoteQueriesValidateCancel(req *remotequeriesv1alpha1.CancelRunRequest) *remoteQueriesControlError {
	if remoteQueriesReasonMissing(req.GetReason()) {
		return &remoteQueriesControlError{
			code:    remoteQueriesErrMissingReason,
			message: "reason must be a non-empty audit string",
		}
	}
	return remoteQueriesValidateIdentity(req.GetRunIdentity())
}

// remoteQueriesValidateIdentity validates the immutable run identity and
// returns the bounded error, or nil when the identity is complete. A
// production policy layer may additionally enforce canonical UUID shapes;
// this runtime check only enforces that all four components are present.
func remoteQueriesValidateIdentity(identity *remotequeriesv1alpha1.RunIdentity) *remoteQueriesControlError {
	switch {
	case identity == nil || identity.GetOrgId() == 0:
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidIdentity,
			message: "run identity must carry a non-zero org_id",
		}
	case identity.GetTaskId() == "":
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidIdentity,
			message: "run identity must carry a non-empty task_id",
		}
	case identity.GetRunId() == "":
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidIdentity,
			message: "run identity must carry a non-empty run_id",
		}
	case identity.GetUploadId() == "":
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidIdentity,
			message: "run identity must carry a non-empty upload_id",
		}
	}
	return nil
}

// remoteQueriesValidateTarget validates the credential-free target and
// returns the bounded error, or nil when the target is valid.
func remoteQueriesValidateTarget(target *remotequeriesv1alpha1.DatabaseTarget) *remoteQueriesControlError {
	if target == nil {
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidTarget,
			message: "target must carry either a network target or a database instance",
		}
	}
	switch t := target.GetTarget().(type) {
	case *remotequeriesv1alpha1.DatabaseTarget_NetworkTarget:
		network := t.NetworkTarget // no getter on oneof wrappers; may be nil
		switch {
		case network == nil || network.GetHost() == "":
			return &remoteQueriesControlError{
				code:    remoteQueriesErrInvalidTarget,
				message: "network target must carry a non-empty host",
			}
		case network.GetPort() == 0 || network.GetPort() > 65535:
			return &remoteQueriesControlError{
				code:    remoteQueriesErrInvalidTarget,
				message: "network target port must be within 1-65535",
			}
		case network.GetDbname() == "":
			return &remoteQueriesControlError{
				code:    remoteQueriesErrInvalidTarget,
				message: "network target must carry a non-empty dbname",
			}
		}
	case *remotequeriesv1alpha1.DatabaseTarget_DatabaseInstance:
		if t.DatabaseInstance == "" {
			return &remoteQueriesControlError{
				code:    remoteQueriesErrInvalidTarget,
				message: "database instance target must carry a non-empty name",
			}
		}
	default:
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidTarget,
			message: "target must carry either a network target or a database instance",
		}
	}
	return nil
}

// remoteQueriesValidateResultDelivery validates the server-owned result
// delivery configuration and returns the bounded error, or nil when it is
// valid.
func remoteQueriesValidateResultDelivery(delivery *remotequeriesv1alpha1.ResultDelivery) *remoteQueriesControlError {
	if delivery == nil {
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidResultDelivery,
			message: "result delivery must be present",
		}
	}
	if delivery.GetArtifactVersion() <= 0 {
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidResultDelivery,
			message: "result delivery must carry a positive artifact version",
		}
	}
	// Note: || short-circuits before the intakeURL fields are dereferenced,
	// so the nil URL returned alongside a parse error is never touched.
	intakeURL, err := url.Parse(delivery.GetIntakeBaseUrl())
	if err != nil || (intakeURL.Scheme != "http" && intakeURL.Scheme != "https") || intakeURL.Host == "" {
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidResultDelivery,
			message: "result delivery must carry an absolute http(s) intake base URL",
		}
	}
	limits := delivery.GetLimits()
	if limits == nil {
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidResultDelivery,
			message: "result delivery must carry server-owned limits",
		}
	}
	if limits.GetMaxFileBytes() == 0 ||
		limits.GetMaxResultBytes() == 0 ||
		limits.GetMaxRowBytes() == 0 ||
		limits.GetMaxColumns() == 0 ||
		limits.GetMaxSchemaBytes() == 0 ||
		limits.GetMaxPages() == 0 ||
		limits.GetTimeoutMs() == 0 {
		return &remoteQueriesControlError{
			code:    remoteQueriesErrInvalidResultDelivery,
			message: "every delivered limit must be greater than zero",
		}
	}
	return nil
}

// remoteQueriesRunKeyFromIdentity builds the map key from a run identity.
// The identity is validated before it is used as a key, so the getters are
// safe to call on nil here.
func remoteQueriesRunKeyFromIdentity(identity *remotequeriesv1alpha1.RunIdentity) remoteQueriesRunKey {
	return remoteQueriesRunKey{
		orgID:    identity.GetOrgId(),
		taskID:   identity.GetTaskId(),
		runID:    identity.GetRunId(),
		uploadID: identity.GetUploadId(),
	}
}

// canonicalCommandDigest computes a deterministic SHA-256 digest of a
// StartRun command's execution semantics: the integration, the target, the
// query, the effective include_schema value, and the full result-delivery
// configuration including every delivered limit.
//
// Excluded from the digest, by design:
//
//   - connection_id and reason: transport and audit context only, so a
//     redelivered or re-issued command with different transport context is
//     still the same command;
//   - trace_context: observability-only by contract, so a retried dispatch
//     under a different trace is still the same command;
//   - the run identity itself: it is the deduplication key the digest is
//     compared under, not command semantics.
//
// The encoding is length-prefixed and labeled per field, so no combination
// of values can collide by concatenation.
func canonicalCommandDigest(req *remotequeriesv1alpha1.StartRunRequest) string {
	h := sha256.New()

	writeCanonicalString(h, "integration", req.GetIntegration())

	switch t := req.GetTarget().GetTarget().(type) {
	case *remotequeriesv1alpha1.DatabaseTarget_NetworkTarget:
		writeCanonicalString(h, "target_kind", "network")
		writeCanonicalString(h, "target_host", t.NetworkTarget.GetHost())
		writeCanonicalUint(h, "target_port", uint64(t.NetworkTarget.GetPort()))
		writeCanonicalString(h, "target_dbname", t.NetworkTarget.GetDbname())
	case *remotequeriesv1alpha1.DatabaseTarget_DatabaseInstance:
		writeCanonicalString(h, "target_kind", "database_instance")
		writeCanonicalString(h, "target_database_instance", t.DatabaseInstance)
	}

	writeCanonicalString(h, "query", req.GetQuery())
	writeCanonicalBool(h, "include_schema", req.GetIncludeSchema())

	delivery := req.GetResultDelivery()
	writeCanonicalUint(h, "artifact_version", uint64(delivery.GetArtifactVersion()))
	writeCanonicalString(h, "intake_base_url", delivery.GetIntakeBaseUrl())

	limits := delivery.GetLimits()
	writeCanonicalUint(h, "max_file_bytes", limits.GetMaxFileBytes())
	writeCanonicalUint(h, "max_result_bytes", limits.GetMaxResultBytes())
	writeCanonicalUint(h, "max_row_bytes", limits.GetMaxRowBytes())
	writeCanonicalUint(h, "max_columns", uint64(limits.GetMaxColumns()))
	writeCanonicalUint(h, "max_schema_bytes", limits.GetMaxSchemaBytes())
	writeCanonicalUint(h, "max_pages", uint64(limits.GetMaxPages()))
	writeCanonicalUint(h, "timeout_ms", limits.GetTimeoutMs())

	return hex.EncodeToString(h.Sum(nil))
}

// writeCanonicalString writes "name=<byte length>:value;" to h. The length
// prefix keeps the encoding unambiguous for any input values.
func writeCanonicalString(h hash.Hash, name, value string) {
	fmt.Fprintf(h, "%s=%d:%s;", name, len(value), value)
}

// writeCanonicalUint writes "name=<hex value>;" to h with a fixed-width
// little-endian encoding.
func writeCanonicalUint(h hash.Hash, name string, value uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], value)
	fmt.Fprintf(h, "%s=%x;", name, buf)
}

// writeCanonicalBool writes "name=<value>;" to h.
func writeCanonicalBool(h hash.Hash, name string, value bool) {
	fmt.Fprintf(h, "%s=%t;", name, value)
}
