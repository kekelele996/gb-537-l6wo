package service

import (
	"context"
	"encoding/json"
	"errors"
	"gorm.io/gorm"
	"net/http"
	"pki-certificate-rollover-impact/backend/internal/algorithm"
	"pki-certificate-rollover-impact/backend/internal/constants"
	"pki-certificate-rollover-impact/backend/internal/dto"
	"pki-certificate-rollover-impact/backend/internal/model"
	"pki-certificate-rollover-impact/backend/internal/repository"
	"pki-certificate-rollover-impact/backend/internal/util"
	"strings"
	"time"
)

type RolloverScenarioService struct {
	scenarios    repository.RolloverScenarioRepository
	anchors      repository.TrustAnchorRepository
	chains       repository.CertificateChainRepository
	services     repository.DependentServiceRepository
	audits       repository.AuditRepository
	signoffs     repository.RiskSignoffRepository
	users        repository.UserRepository
	transactions repository.TransactionManager
	now          func() time.Time
}

func NewRolloverScenarioService(scenarios repository.RolloverScenarioRepository, anchors repository.TrustAnchorRepository, chains repository.CertificateChainRepository, services repository.DependentServiceRepository, audits repository.AuditRepository, signoffs repository.RiskSignoffRepository, users repository.UserRepository, transactions repository.TransactionManager) *RolloverScenarioService {
	return &RolloverScenarioService{scenarios: scenarios, anchors: anchors, chains: chains, services: services, audits: audits, signoffs: signoffs, users: users, transactions: transactions, now: func() time.Time { return time.Now().UTC() }}
}

func requireScenarioOwnership(actor util.Actor, scenario model.RolloverScenario) error {
	if actor.Role == string(constants.RoleAdmin) || actor.Role == string(constants.RolePKIOperator) || scenario.CreatedBy == actor.UserID {
		return nil
	}
	return util.NewError(http.StatusForbidden, util.CodeForbidden, "only the scenario creator or a PKI administrator may manage this scenario")
}
func (s *RolloverScenarioService) Create(ctx context.Context, request dto.CreateRolloverScenarioRequest, actor util.Actor, requestID string) (dto.RolloverScenarioResponse, error) {
	if err := validateRequest(request); err != nil {
		return dto.RolloverScenarioResponse{}, err
	}
	if request.OldAnchorID == request.NewAnchorID {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusBadRequest, util.CodeValidation, "old and new trust anchors must be distinct")
	}
	anchorIDs := uniqueIDs([]uint{request.OldAnchorID, request.NewAnchorID})
	anchors, err := s.anchors.GetByIDs(ctx, anchorIDs)
	if err != nil || len(anchors) != 2 {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusBadRequest, util.CodeValidation, "both trust anchors must exist")
	}
	candidateIDs := uniqueIDs(request.CandidateChainIDs)
	candidates, err := s.chains.GetByIDs(ctx, candidateIDs)
	if err != nil || len(candidates) != len(candidateIDs) {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusBadRequest, util.CodeValidation, "one or more candidate chains do not exist")
	}
	allChains, _, err := s.chains.List(ctx, dto.CertificateChainQuery{Page: 1, PageSize: 200})
	if err != nil {
		return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to freeze certificate chains", err)
	}
	allServices, err := s.services.All(ctx)
	if err != nil {
		return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to freeze dependency graph", err)
	}
	snapshot, err := buildSnapshot(request.Name, request.OldAnchorID, request.NewAnchorID, request.OverlapStart, request.OverlapEnd, request.SimulationTime, candidateIDs, anchors, allChains, allServices)
	if err != nil {
		return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusUnprocessableEntity, util.CodeValidation, "rollover input is invalid", err)
	}
	if err := algorithm.ValidateSnapshot(snapshot); err != nil {
		return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusUnprocessableEntity, util.CodeValidation, "rollover input is invalid", err)
	}
	inputHash, err := snapshot.Hash()
	if err != nil {
		return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to hash frozen input", err)
	}
	snapshotJSON, _ := snapshot.Canonical()
	candidateJSON, _ := encode(candidateIDs)
	now := s.now()
	scenario := model.RolloverScenario{Name: strings.TrimSpace(request.Name), OldAnchorID: request.OldAnchorID, NewAnchorID: request.NewAnchorID, OverlapStart: request.OverlapStart.UTC(), OverlapEnd: request.OverlapEnd.UTC(), CandidateChainIDs: candidateJSON, AlgorithmVersion: algorithm.Version, InputHash: inputHash, InputSnapshot: snapshotJSON, SimulationTime: request.SimulationTime.UTC(), AffectedServicesJSON: "[]", BrokenPathsJSON: "[]", PathEvidenceJSON: "[]", ScenarioState: string(constants.ScenarioDraft), Explanation: "Frozen input is ready for offline simulation.", CreatedBy: actor.UserID, CreatedByName: actor.Username, CreatedAt: now, UpdatedAt: now}
	err = s.transactions.WithinTransaction(ctx, func(txCtx context.Context) error {
		if createErr := s.scenarios.Create(txCtx, &scenario); createErr != nil {
			return createErr
		}
		return recordAudit(txCtx, s.audits, actor, requestID, "rollover_scenario", scenario.ID, "create_frozen_draft", nil, scenario, inputHash, algorithm.Version, &scenario.SimulationTime, 0, "frozen anchors, chains, and dependency graph")
	})
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusConflict, util.CodeConflict, "an identical frozen scenario already exists", err)
		}
		return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to create rollover scenario", err)
	}
	return s.Get(ctx, scenario.ID)
}
func (s *RolloverScenarioService) Simulate(ctx context.Context, id uint, idempotencyKey string, actor util.Actor, requestID string) (dto.RolloverScenarioResponse, bool, error) {
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" {
		return dto.RolloverScenarioResponse{}, false, util.NewError(http.StatusBadRequest, util.CodeIdempotency, "Idempotency-Key header is required")
	}
	if len(idempotencyKey) > 128 {
		return dto.RolloverScenarioResponse{}, false, util.NewError(http.StatusBadRequest, util.CodeValidation, "Idempotency-Key must not exceed 128 characters")
	}
	scenario, err := s.scenarios.GetByID(ctx, id, false)
	if err != nil {
		return dto.RolloverScenarioResponse{}, false, util.NotFound("rollover scenario")
	}
	if err := requireScenarioOwnership(actor, scenario); err != nil {
		return dto.RolloverScenarioResponse{}, false, err
	}
	if prior, err := s.scenarios.FindByIdempotencyKey(ctx, idempotencyKey); err == nil {
		if prior.ID != id {
			return dto.RolloverScenarioResponse{}, false, util.NewError(http.StatusConflict, util.CodeIdempotency, "Idempotency-Key is already bound to another rollover scenario")
		}
		return dto.NewRolloverScenarioResponse(prior, s.now()), true, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return dto.RolloverScenarioResponse{}, false, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to check idempotency key", err)
	}
	if scenario.ScenarioState != "draft" {
		return dto.RolloverScenarioResponse{}, false, util.NewError(http.StatusConflict, util.CodeStateTransition, "only draft scenarios can be simulated")
	}
	snapshot, err := algorithm.DecodeSnapshot(scenario.InputSnapshot)
	if err != nil {
		return dto.RolloverScenarioResponse{}, false, util.WrapError(http.StatusUnprocessableEntity, util.CodeValidation, "frozen scenario snapshot is invalid", err)
	}
	started := time.Now()
	result, err := algorithm.Simulate(snapshot)
	duration := time.Since(started).Milliseconds()
	if err != nil {
		return dto.RolloverScenarioResponse{}, false, util.WrapError(http.StatusUnprocessableEntity, util.CodeValidation, "rollover simulation failed", err)
	}
	affectedJSON, _ := encode(result.AffectedServices)
	pathsJSON, _ := encode(result.BrokenPaths)
	evidenceJSON, _ := encode(result.Evidence)
	before := scenario
	updates := map[string]any{"affected_services_json": affectedJSON, "broken_paths_json": pathsJSON, "path_evidence_json": evidenceJSON, "explanation": result.Explanation, "duration_ms": duration, "idempotency_key": idempotencyKey}
	err = s.transactions.WithinTransaction(ctx, func(txCtx context.Context) error {
		changed, completeErr := s.scenarios.CompleteSimulation(txCtx, id, updates)
		if completeErr != nil {
			return completeErr
		}
		if !changed {
			return util.NewError(http.StatusConflict, util.CodeConflict, "scenario state changed concurrently")
		}
		scenario.ScenarioState = "simulated"
		scenario.AffectedServicesJSON = affectedJSON
		scenario.BrokenPathsJSON = pathsJSON
		scenario.PathEvidenceJSON = evidenceJSON
		scenario.Explanation = result.Explanation
		scenario.DurationMS = duration
		scenario.IdempotencyKey = idempotencyKey
		return recordAudit(txCtx, s.audits, actor, requestID, "rollover_scenario", id, "simulate", before, scenario, scenario.InputHash, scenario.AlgorithmVersion, &scenario.SimulationTime, duration, result.Explanation)
	})
	if err != nil {
		return dto.RolloverScenarioResponse{}, false, err
	}
	response, getErr := s.Get(ctx, id)
	return response, false, getErr
}
func (s *RolloverScenarioService) Get(ctx context.Context, id uint) (dto.RolloverScenarioResponse, error) {
	scenario, err := s.scenarios.GetByID(ctx, id, true)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return dto.RolloverScenarioResponse{}, util.NotFound("rollover scenario")
		}
		return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to load rollover scenario", err)
	}
	data, err := s.risks(ctx, []model.RolloverScenario{scenario})
	if err != nil {
		return dto.RolloverScenarioResponse{}, err
	}
	return s.responseWithRisk(scenario, data[scenario.ID]), nil
}
func (s *RolloverScenarioService) List(ctx context.Context, query dto.RolloverScenarioQuery) (dto.RolloverScenarioListResponse, error) {
	scenarios, total, err := s.scenarios.List(ctx, query)
	if err != nil {
		return dto.RolloverScenarioListResponse{}, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to list rollover scenarios", err)
	}
	response := dto.RolloverScenarioListResponse{Items: make([]dto.RolloverScenarioResponse, 0, len(scenarios)), Total: total, Page: query.Page, Size: query.PageSize}
	riskByScenario, err := s.risks(ctx, scenarios)
	if err != nil {
		return dto.RolloverScenarioListResponse{}, err
	}
	for _, scenario := range scenarios {
		response.Items = append(response.Items, s.responseWithRisk(scenario, riskByScenario[scenario.ID]))
	}
	return response, nil
}

type scenarioRiskData struct {
	summary         dto.RiskSignoffSummary
	affected        []algorithm.AffectedService
	currentHash     string
	currentServices []model.DependentService
}

func (s *RolloverScenarioService) responseWithRisk(scenario model.RolloverScenario, data *scenarioRiskData) dto.RolloverScenarioResponse {
	response := dto.NewRolloverScenarioResponse(scenario, s.now())
	if data != nil {
		response.RiskSignoffs = data.summary
	}
	return response
}

func (s *RolloverScenarioService) risks(ctx context.Context, scenarios []model.RolloverScenario) (map[uint]*scenarioRiskData, error) {
	result := map[uint]*scenarioRiskData{}
	if len(scenarios) == 0 {
		return result, nil
	}
	allServices, err := s.services.All(ctx)
	if err != nil {
		return nil, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to load current dependency graph", err)
	}
	allChains, _, err := s.chains.List(ctx, dto.CertificateChainQuery{Page: 1, PageSize: 200})
	if err != nil {
		return nil, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to load current certificate chains", err)
	}
	anchorIDSet := map[uint]bool{}
	for _, chain := range allChains {
		anchorIDSet[chain.TrustAnchorID] = true
	}
	for _, scenario := range scenarios {
		anchorIDSet[scenario.OldAnchorID] = true
		anchorIDSet[scenario.NewAnchorID] = true
	}
	anchorIDs := make([]uint, 0, len(anchorIDSet))
	for id := range anchorIDSet {
		anchorIDs = append(anchorIDs, id)
	}
	allAnchors, err := s.anchors.GetByIDs(ctx, anchorIDs)
	if err != nil {
		return nil, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to load current trust anchors", err)
	}
	scenarioIDs := make([]uint, 0, len(scenarios))
	for _, scenario := range scenarios {
		scenarioIDs = append(scenarioIDs, scenario.ID)
	}
	signoffsByScenario, err := s.signoffs.ListByScenarioIDs(ctx, scenarioIDs)
	if err != nil {
		return nil, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to load risk signoffs", err)
	}
	for _, scenario := range scenarios {
		snapshot, snapshotErr := buildSnapshot(scenario.Name, scenario.OldAnchorID, scenario.NewAnchorID, scenario.OverlapStart, scenario.OverlapEnd, scenario.SimulationTime, mustUintList(scenario.CandidateChainIDs), allAnchors, allChains, allServices)
		currentHash := ""
		if snapshotErr == nil {
			currentHash, _ = snapshot.Hash()
		}
		affected := []algorithm.AffectedService{}
		_ = json.Unmarshal([]byte(scenario.AffectedServicesJSON), &affected)
		summary := dto.BuildRiskSignoffSummary(scenario, affected, allServices, signoffsByScenario[scenario.ID], currentHash)
		result[scenario.ID] = &scenarioRiskData{summary: summary, affected: affected, currentHash: currentHash, currentServices: allServices}
	}
	return result, nil
}

func mustUintList(raw string) []uint {
	values := []uint{}
	_ = json.Unmarshal([]byte(raw), &values)
	return values
}

func riskReadinessFailure(summary dto.RiskSignoffSummary) string {
	if summary.InputChanged {
		return "frozen input has changed; rerun the simulation before requesting risk signoff"
	}
	missing := []string{}
	for _, requirement := range summary.Requirements {
		if requirement.Status != "signed" {
			missing = append(missing, requirement.ServiceCode+"："+requirement.InvalidReason)
		}
	}
	if len(missing) != 0 {
		return "critical affected services have not signed the risk: " + strings.Join(missing, "; ")
	}
	return ""
}
func (s *RolloverScenarioService) Transition(ctx context.Context, id uint, request dto.RolloverScenarioTransitionRequest, actor util.Actor, requestID string) (dto.RolloverScenarioResponse, error) {
	if err := validateRequest(request); err != nil {
		return dto.RolloverScenarioResponse{}, err
	}
	scenario, err := s.scenarios.GetByID(ctx, id, false)
	if err != nil {
		return dto.RolloverScenarioResponse{}, util.NotFound("rollover scenario")
	}
	from, to := constants.ScenarioState(scenario.ScenarioState), constants.ScenarioState(request.ToState)
	if to != constants.ScenarioVerified {
		if err := requireScenarioOwnership(actor, scenario); err != nil {
			return dto.RolloverScenarioResponse{}, err
		}
	}
	if !constants.CanTransitionScenario(from, to) {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusConflict, util.CodeStateTransition, "illegal scenario transition from "+scenario.ScenarioState+" to "+request.ToState)
	}
	if to == constants.ScenarioVerified && !scenario.ReviewerSeparated(actor.UserID) {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusConflict, util.CodeReviewerConflict, "scenario creator cannot verify their own simulation")
	}
	if to == constants.ScenarioReady || to == constants.ScenarioExecuting {
		riskData, riskErr := s.risks(ctx, []model.RolloverScenario{scenario})
		if riskErr != nil {
			return dto.RolloverScenarioResponse{}, riskErr
		}
		if reason := riskReadinessFailure(riskData[id].summary); reason != "" {
			return dto.RolloverScenarioResponse{}, util.NewError(http.StatusConflict, util.CodeStateTransition, reason)
		}
	}
	updates := map[string]any{}
	if to == constants.ScenarioVerified {
		updates["verified_by"] = actor.UserID
		updates["verified_by_name"] = actor.Username
	}
	if to == constants.ScenarioRollback {
		updates["rollback_record"] = strings.TrimSpace(request.Comment)
	}
	before := scenario
	err = s.transactions.WithinTransaction(ctx, func(txCtx context.Context) error {
		changed, transitionErr := s.scenarios.Transition(txCtx, id, scenario.ScenarioState, request.ToState, updates)
		if transitionErr != nil {
			return transitionErr
		}
		if !changed {
			return util.NewError(http.StatusConflict, util.CodeConflict, "scenario state changed concurrently")
		}
		scenario.ScenarioState = request.ToState
		if to == constants.ScenarioVerified {
			scenario.VerifiedBy = &actor.UserID
			scenario.VerifiedByName = actor.Username
		}
		if to == constants.ScenarioRollback {
			scenario.RollbackRecord = strings.TrimSpace(request.Comment)
		}
		return recordAudit(txCtx, s.audits, actor, requestID, "rollover_scenario", id, "transition", before, scenario, scenario.InputHash, scenario.AlgorithmVersion, &scenario.SimulationTime, 0, request.Comment)
	})
	if err != nil {
		return dto.RolloverScenarioResponse{}, err
	}
	return s.Get(ctx, id)
}
func (s *RolloverScenarioService) Replay(ctx context.Context, id uint, actor util.Actor, requestID string) (dto.RolloverScenarioResponse, error) {
	scenario, err := s.scenarios.GetByID(ctx, id, false)
	if err != nil {
		return dto.RolloverScenarioResponse{}, util.NotFound("rollover scenario")
	}
	if err := requireScenarioOwnership(actor, scenario); err != nil {
		return dto.RolloverScenarioResponse{}, err
	}
	if scenario.ScenarioState == "draft" {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusConflict, util.CodeStateTransition, "draft scenario has no stored result to replay")
	}
	snapshot, err := algorithm.DecodeSnapshot(scenario.InputSnapshot)
	if err != nil {
		return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusUnprocessableEntity, util.CodeValidation, "frozen scenario snapshot is invalid", err)
	}
	result, err := algorithm.Simulate(snapshot)
	if err != nil {
		return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusUnprocessableEntity, util.CodeValidation, "scenario replay failed", err)
	}
	affectedJSON, _ := encode(result.AffectedServices)
	pathsJSON, _ := encode(result.BrokenPaths)
	evidenceJSON, _ := encode(result.Evidence)
	passed := affectedJSON == scenario.AffectedServicesJSON && pathsJSON == scenario.BrokenPathsJSON && evidenceJSON == scenario.PathEvidenceJSON && result.Explanation == scenario.Explanation
	after := scenario
	after.ReplayVerified = passed
	err = s.transactions.WithinTransaction(ctx, func(txCtx context.Context) error {
		if updateErr := s.scenarios.SetReplayVerified(txCtx, id, passed); updateErr != nil {
			return util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to store replay evidence", updateErr)
		}
		return recordAudit(txCtx, s.audits, actor, requestID, "rollover_scenario", id, "replay", scenario, after, scenario.InputHash, scenario.AlgorithmVersion, &scenario.SimulationTime, 0, result.Explanation)
	})
	if err != nil {
		return dto.RolloverScenarioResponse{}, err
	}
	if !passed {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusConflict, util.CodeConflict, "replay differs from frozen historical result")
	}
	return s.Get(ctx, id)
}
func (s *RolloverScenarioService) SignRisk(ctx context.Context, id uint, request dto.RiskSignoffRequest, actor util.Actor, requestID string) (dto.RolloverScenarioResponse, error) {
	if err := validateRequest(request); err != nil {
		return dto.RolloverScenarioResponse{}, err
	}
	scenario, err := s.scenarios.GetByID(ctx, id, false)
	if err != nil {
		return dto.RolloverScenarioResponse{}, util.NotFound("rollover scenario")
	}
	if scenario.ScenarioState != string(constants.ScenarioSimulated) && scenario.ScenarioState != string(constants.ScenarioReady) {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusConflict, util.CodeStateTransition, "risk can be signed only after the simulation is stored")
	}
	user, err := s.users.GetByID(ctx, actor.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return dto.RolloverScenarioResponse{}, util.NewError(http.StatusForbidden, util.CodeForbidden, "risk signoff owner was not found")
		}
		return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to verify risk signoff owner", err)
	}
	if !user.Active || user.Role != string(constants.RoleServiceOwner) {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusForbidden, util.CodeForbidden, "only an active service team owner can sign risk")
	}
	riskData, err := s.risks(ctx, []model.RolloverScenario{scenario})
	if err != nil {
		return dto.RolloverScenarioResponse{}, err
	}
	data := riskData[id]
	if data.currentHash != scenario.InputHash {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusConflict, util.CodeStateTransition, "frozen input has changed; rerun the simulation before signing risk")
	}
	var requirement *dto.CriticalServiceRequirement
	for index := range data.summary.Requirements {
		if data.summary.Requirements[index].ServiceID == request.ServiceID {
			requirement = &data.summary.Requirements[index]
			break
		}
	}
	if requirement == nil {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusNotFound, util.CodeNotFound, "service is not a critical service affected by this scenario")
	}
	var current *model.DependentService
	for index := range data.currentServices {
		if data.currentServices[index].ID == request.ServiceID {
			current = &data.currentServices[index]
			break
		}
	}
	if current == nil {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusConflict, util.CodeStateTransition, "current service register does not contain this critical service")
	}
	if current.ServiceState != string(constants.ServiceActive) {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusConflict, util.CodeStateTransition, "inactive critical service requires a new frozen simulation")
	}
	if user.Team != current.OwnerTeam || current.OwnerTeam != requirement.OwnerTeam {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusForbidden, util.CodeForbidden, "only the owning team's service owner can sign this risk")
	}
	comment := strings.TrimSpace(request.Comment)
	if comment == "" {
		comment = "团队负责人确认并签收该轮换风险。"
	}
	signoff := model.ScenarioRiskSignoff{ScenarioID: scenario.ID, ServiceID: current.ID, ServiceCode: current.ServiceCode, OwnerTeam: current.OwnerTeam, InputHash: scenario.InputHash, SignoffBy: user.ID, SignoffByName: user.Username, Comment: comment}
	err = s.transactions.WithinTransaction(ctx, func(txCtx context.Context) error {
		if upsertErr := s.signoffs.Upsert(txCtx, &signoff); upsertErr != nil {
			return upsertErr
		}
		return recordAudit(txCtx, s.audits, actor, requestID, "rollover_risk_signoff", signoff.ID, "sign_risk", nil, signoff, scenario.InputHash, scenario.AlgorithmVersion, &scenario.SimulationTime, 0, comment)
	})
	if err != nil {
		return dto.RolloverScenarioResponse{}, err
	}
	return s.Get(ctx, id)
}
func (s *RolloverScenarioService) Compare(ctx context.Context, id, otherID uint) (map[string]any, error) {
	first, err := s.scenarios.GetByID(ctx, id, false)
	if err != nil {
		return nil, util.NotFound("first rollover scenario")
	}
	second, err := s.scenarios.GetByID(ctx, otherID, false)
	if err != nil {
		return nil, util.NotFound("second rollover scenario")
	}
	var firstAffected, secondAffected []algorithm.AffectedService
	var firstPaths, secondPaths []algorithm.BrokenPath
	_ = json.Unmarshal([]byte(first.AffectedServicesJSON), &firstAffected)
	_ = json.Unmarshal([]byte(second.AffectedServicesJSON), &secondAffected)
	_ = json.Unmarshal([]byte(first.BrokenPathsJSON), &firstPaths)
	_ = json.Unmarshal([]byte(second.BrokenPathsJSON), &secondPaths)
	return map[string]any{"first_id": first.ID, "second_id": second.ID, "same_algorithm": first.AlgorithmVersion == second.AlgorithmVersion, "same_input": first.InputHash == second.InputHash, "summary": algorithm.Compare(algorithm.Result{AffectedServices: firstAffected, BrokenPaths: firstPaths}, algorithm.Result{AffectedServices: secondAffected, BrokenPaths: secondPaths})}, nil
}
