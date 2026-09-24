package dto

import (
	"encoding/json"
	"sort"
	"time"

	"pki-certificate-rollover-impact/backend/internal/algorithm"
	"pki-certificate-rollover-impact/backend/internal/model"
)

type CreateRolloverScenarioRequest struct {
	Name              string    `json:"name" validate:"required,min=3,max=180"`
	OldAnchorID       uint      `json:"old_anchor_id" validate:"required"`
	NewAnchorID       uint      `json:"new_anchor_id" validate:"required"`
	OverlapStart      time.Time `json:"overlap_start" validate:"required"`
	OverlapEnd        time.Time `json:"overlap_end" validate:"required"`
	CandidateChainIDs []uint    `json:"candidate_chain_ids" validate:"required,min=1,max=32,dive,gt=0"`
	SimulationTime    time.Time `json:"simulation_time" validate:"required"`
}
type RolloverScenarioTransitionRequest struct {
	ToState string `json:"to_state" validate:"required,oneof=draft ready executing verified rollback"`
	Comment string `json:"comment" validate:"max=1000"`
}
type ScenarioRiskSignoffRequest struct {
	ServiceID uint   `json:"service_id" validate:"required"`
	Comment   string `json:"comment" validate:"max=1000"`
}
type RolloverScenarioQuery struct {
	State     string
	CreatedBy uint
	Page      int
	PageSize  int
}

type ScenarioRiskSignoffResponse struct {
	ID             uint      `json:"id"`
	ServiceID      uint      `json:"service_id"`
	ServiceCode    string    `json:"service_code"`
	ServiceName    string    `json:"service_name"`
	OwnerTeam      string    `json:"owner_team"`
	Criticality    string    `json:"criticality"`
	InputHash      string    `json:"input_hash"`
	AcceptedBy     uint      `json:"accepted_by"`
	AcceptedByName string    `json:"accepted_by_name"`
	Comment        string    `json:"comment"`
	Valid          bool      `json:"valid"`
	InvalidReason  string    `json:"invalid_reason"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
type ScenarioRiskSignoffRequirement struct {
	ServiceID     uint   `json:"service_id"`
	ServiceCode   string `json:"service_code"`
	ServiceName   string `json:"service_name"`
	OwnerTeam     string `json:"owner_team"`
	Criticality   string `json:"criticality"`
	Signed        bool   `json:"signed"`
	Valid         bool   `json:"valid"`
	InvalidReason string `json:"invalid_reason"`
}
type ScenarioRiskSignoffSummary struct {
	Required                 bool                             `json:"required"`
	Ready                    bool                             `json:"ready"`
	PendingServiceIDs        []uint                           `json:"pending_service_ids"`
	InvalidServiceIDs        []uint                           `json:"invalid_service_ids"`
	RequiredCriticalServices []ScenarioRiskSignoffRequirement `json:"required_critical_services"`
	Signoffs                 []ScenarioRiskSignoffResponse    `json:"signoffs"`
}

type RolloverScenarioResponse struct {
	ID                   uint                          `json:"id"`
	Name                 string                        `json:"name"`
	OldAnchorID          uint                          `json:"old_anchor_id"`
	NewAnchorID          uint                          `json:"new_anchor_id"`
	OldAnchor            *TrustAnchorResponse          `json:"old_anchor,omitempty"`
	NewAnchor            *TrustAnchorResponse          `json:"new_anchor,omitempty"`
	OverlapStart         time.Time                     `json:"overlap_start"`
	OverlapEnd           time.Time                     `json:"overlap_end"`
	CandidateChainIDs    []uint                        `json:"candidate_chain_ids"`
	AlgorithmVersion     string                        `json:"algorithm_version"`
	InputHash            string                        `json:"input_hash"`
	SimulationTime       time.Time                     `json:"simulation_time"`
	AffectedServicesJSON []algorithm.AffectedService   `json:"affected_services_json"`
	BrokenPathsJSON      []algorithm.BrokenPath        `json:"broken_paths_json"`
	PathEvidenceJSON     []algorithm.TimepointEvidence `json:"path_evidence_json"`
	ScenarioState        string                        `json:"scenario_state"`
	Explanation          string                        `json:"explanation"`
	CreatedBy            uint                          `json:"created_by"`
	CreatedByName        string                        `json:"created_by_name"`
	VerifiedBy           *uint                         `json:"verified_by,omitempty"`
	VerifiedByName       string                        `json:"verified_by_name"`
	ReplayVerified       bool                          `json:"replay_verified"`
	DurationMS           int64                         `json:"duration_ms"`
	RollbackRecord       string                        `json:"rollback_record"`
	RiskSignoffs         ScenarioRiskSignoffSummary    `json:"risk_signoffs"`
	CreatedAt            time.Time                     `json:"created_at"`
	UpdatedAt            time.Time                     `json:"updated_at"`
}
type RolloverScenarioListResponse struct {
	Items []RolloverScenarioResponse `json:"items"`
	Total int64                      `json:"total"`
	Page  int                        `json:"page"`
	Size  int                        `json:"size"`
}

func NewRolloverScenarioResponse(scenario model.RolloverScenario, now time.Time) RolloverScenarioResponse {
	candidateIDs := []uint{}
	affected := []algorithm.AffectedService{}
	paths := []algorithm.BrokenPath{}
	evidence := []algorithm.TimepointEvidence{}
	_ = json.Unmarshal([]byte(scenario.CandidateChainIDs), &candidateIDs)
	_ = json.Unmarshal([]byte(scenario.AffectedServicesJSON), &affected)
	_ = json.Unmarshal([]byte(scenario.BrokenPathsJSON), &paths)
	_ = json.Unmarshal([]byte(scenario.PathEvidenceJSON), &evidence)
	response := RolloverScenarioResponse{ID: scenario.ID, Name: scenario.Name, OldAnchorID: scenario.OldAnchorID, NewAnchorID: scenario.NewAnchorID, OverlapStart: scenario.OverlapStart, OverlapEnd: scenario.OverlapEnd, CandidateChainIDs: candidateIDs, AlgorithmVersion: scenario.AlgorithmVersion, InputHash: scenario.InputHash, SimulationTime: scenario.SimulationTime, AffectedServicesJSON: affected, BrokenPathsJSON: paths, PathEvidenceJSON: evidence, ScenarioState: scenario.ScenarioState, Explanation: scenario.Explanation, CreatedBy: scenario.CreatedBy, CreatedByName: scenario.CreatedByName, VerifiedBy: scenario.VerifiedBy, VerifiedByName: scenario.VerifiedByName, ReplayVerified: scenario.ReplayVerified, DurationMS: scenario.DurationMS, RollbackRecord: scenario.RollbackRecord, RiskSignoffs: BuildRiskSignoffSummary(scenario, nil, nil), CreatedAt: scenario.CreatedAt, UpdatedAt: scenario.UpdatedAt}
	if scenario.OldAnchor.ID != 0 {
		anchor := NewTrustAnchorResponse(scenario.OldAnchor, 0, now)
		response.OldAnchor = &anchor
	}
	if scenario.NewAnchor.ID != 0 {
		anchor := NewTrustAnchorResponse(scenario.NewAnchor, 0, now)
		response.NewAnchor = &anchor
	}
	return response
}

func criticalAffectedServices(scenario model.RolloverScenario) []algorithm.AffectedService {
	affected := []algorithm.AffectedService{}
	_ = json.Unmarshal([]byte(scenario.AffectedServicesJSON), &affected)
	byID := map[uint]algorithm.AffectedService{}
	for _, service := range affected {
		if service.Criticality == "critical" {
			byID[service.ServiceID] = service
		}
	}
	ids := make([]uint, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	result := make([]algorithm.AffectedService, 0, len(ids))
	for _, id := range ids {
		result = append(result, byID[id])
	}
	return result
}

func BuildRiskSignoffSummary(scenario model.RolloverScenario, signoffs []model.ScenarioRiskSignoff, currentServices []model.DependentService) ScenarioRiskSignoffSummary {
	criticalServices := criticalAffectedServices(scenario)
	currentByID := map[uint]model.DependentService{}
	for _, service := range currentServices {
		currentByID[service.ID] = service
	}
	signoffByID := map[uint]model.ScenarioRiskSignoff{}
	for _, signoff := range signoffs {
		if signoff.ScenarioID == scenario.ID {
			signoffByID[signoff.ServiceID] = signoff
		}
	}
	summary := ScenarioRiskSignoffSummary{Required: len(criticalServices) > 0, Ready: len(criticalServices) > 0, PendingServiceIDs: []uint{}, InvalidServiceIDs: []uint{}, RequiredCriticalServices: []ScenarioRiskSignoffRequirement{}, Signoffs: []ScenarioRiskSignoffResponse{}}
	for _, critical := range criticalServices {
		signoff, signed := signoffByID[critical.ServiceID]
		requirement := ScenarioRiskSignoffRequirement{ServiceID: critical.ServiceID, ServiceCode: critical.ServiceCode, ServiceName: critical.ServiceName, OwnerTeam: critical.OwnerTeam, Criticality: critical.Criticality, Signed: signed}
		if current, exists := currentByID[critical.ServiceID]; exists {
			requirement.ServiceName = current.Name
			requirement.OwnerTeam = current.OwnerTeam
			requirement.Criticality = current.Criticality
		}
		if !signed {
			requirement.InvalidReason = "等待对应团队负责人签收风险"
			summary.PendingServiceIDs = append(summary.PendingServiceIDs, critical.ServiceID)
		} else {
			requirement.InvalidReason = riskSignoffInvalidReason(scenario.InputHash, signoff, currentByID[critical.ServiceID], true)
			requirement.Valid = requirement.InvalidReason == ""
			if requirement.InvalidReason != "" {
				summary.InvalidServiceIDs = append(summary.InvalidServiceIDs, critical.ServiceID)
			}
		}
		summary.RequiredCriticalServices = append(summary.RequiredCriticalServices, requirement)
	}
	for _, critical := range criticalServices {
		signoff := signoffByID[critical.ServiceID]
		if signoff.ID == 0 {
			continue
		}
		current := currentByID[critical.ServiceID]
		item := ScenarioRiskSignoffResponse{ID: signoff.ID, ServiceID: signoff.ServiceID, ServiceCode: signoff.ServiceCode, ServiceName: current.Name, OwnerTeam: signoff.OwnerTeam, Criticality: current.Criticality, InputHash: signoff.InputHash, AcceptedBy: signoff.AcceptedBy, AcceptedByName: signoff.AcceptedByName, Comment: signoff.Comment, InvalidReason: riskSignoffInvalidReason(scenario.InputHash, signoff, current, false), CreatedAt: signoff.CreatedAt, UpdatedAt: signoff.UpdatedAt}
		item.Valid = item.InvalidReason == ""
		summary.Signoffs = append(summary.Signoffs, item)
	}
	summary.Ready = len(criticalServices) > 0 && len(summary.PendingServiceIDs) == 0 && len(summary.InvalidServiceIDs) == 0
	return summary
}

func riskSignoffInvalidReason(currentHash string, signoff model.ScenarioRiskSignoff, current model.DependentService, missingIsInvalid bool) string {
	if current.ID == 0 {
		if missingIsInvalid {
			return "签收服务已不在当前依赖服务中"
		}
		return ""
	}
	if signoff.InputHash != currentHash {
		return "签收绑定的冻结输入哈希已变化"
	}
	if current.ServiceState != "active" || current.Criticality != "critical" {
		return "关键服务状态已变化，原签收失效"
	}
	if signoff.OwnerTeam != current.OwnerTeam {
		return "服务归属团队已变化，原签收失效"
	}
	return ""
}
