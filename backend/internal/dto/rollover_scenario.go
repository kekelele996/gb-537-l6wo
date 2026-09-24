package dto

import (
	"encoding/json"
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
type RiskSignoffRequest struct {
	ServiceID uint   `json:"service_id" validate:"required"`
	Comment   string `json:"comment" validate:"max=1000"`
}
type RolloverScenarioQuery struct {
	State     string
	CreatedBy uint
	Page      int
	PageSize  int
}

type RiskSignoffResponse struct {
	ID            uint      `json:"id"`
	ScenarioID    uint      `json:"scenario_id"`
	ServiceID     uint      `json:"service_id"`
	ServiceCode   string    `json:"service_code"`
	OwnerTeam     string    `json:"owner_team"`
	InputHash     string    `json:"input_hash"`
	SignoffBy     uint      `json:"signoff_by"`
	SignoffByName string    `json:"signoff_by_name"`
	Comment       string    `json:"comment"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type CriticalServiceRequirement struct {
	ServiceID     uint                 `json:"service_id"`
	ServiceCode   string               `json:"service_code"`
	ServiceName   string               `json:"service_name"`
	OwnerTeam     string               `json:"owner_team"`
	Criticality   string               `json:"criticality"`
	CurrentTeam   string               `json:"current_team"`
	Status        string               `json:"status"`
	InvalidReason string               `json:"invalid_reason,omitempty"`
	Signoff       *RiskSignoffResponse `json:"signoff,omitempty"`
}

type RiskSignoffSummary struct {
	RequiredCount int                          `json:"required_count"`
	SignedCount   int                          `json:"signed_count"`
	Ready         bool                         `json:"ready"`
	CurrentHash   string                       `json:"current_hash"`
	InputChanged  bool                         `json:"input_changed"`
	Requirements  []CriticalServiceRequirement `json:"requirements"`
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
	RiskSignoffs         RiskSignoffSummary            `json:"risk_signoffs"`
	Explanation          string                        `json:"explanation"`
	CreatedBy            uint                          `json:"created_by"`
	CreatedByName        string                        `json:"created_by_name"`
	VerifiedBy           *uint                         `json:"verified_by,omitempty"`
	VerifiedByName       string                        `json:"verified_by_name"`
	ReplayVerified       bool                          `json:"replay_verified"`
	DurationMS           int64                         `json:"duration_ms"`
	RollbackRecord       string                        `json:"rollback_record"`
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
	response := RolloverScenarioResponse{ID: scenario.ID, Name: scenario.Name, OldAnchorID: scenario.OldAnchorID, NewAnchorID: scenario.NewAnchorID, OverlapStart: scenario.OverlapStart, OverlapEnd: scenario.OverlapEnd, CandidateChainIDs: candidateIDs, AlgorithmVersion: scenario.AlgorithmVersion, InputHash: scenario.InputHash, SimulationTime: scenario.SimulationTime, AffectedServicesJSON: affected, BrokenPathsJSON: paths, PathEvidenceJSON: evidence, ScenarioState: scenario.ScenarioState, RiskSignoffs: EmptyRiskSignoffSummary(scenario.InputHash), Explanation: scenario.Explanation, CreatedBy: scenario.CreatedBy, CreatedByName: scenario.CreatedByName, VerifiedBy: scenario.VerifiedBy, VerifiedByName: scenario.VerifiedByName, ReplayVerified: scenario.ReplayVerified, DurationMS: scenario.DurationMS, RollbackRecord: scenario.RollbackRecord, CreatedAt: scenario.CreatedAt, UpdatedAt: scenario.UpdatedAt}
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

func EmptyRiskSignoffSummary(hash string) RiskSignoffSummary {
	return RiskSignoffSummary{CurrentHash: hash, Requirements: []CriticalServiceRequirement{}}
}

func NewRiskSignoffResponse(signoff model.ScenarioRiskSignoff) RiskSignoffResponse {
	return RiskSignoffResponse{ID: signoff.ID, ScenarioID: signoff.ScenarioID, ServiceID: signoff.ServiceID, ServiceCode: signoff.ServiceCode, OwnerTeam: signoff.OwnerTeam, InputHash: signoff.InputHash, SignoffBy: signoff.SignoffBy, SignoffByName: signoff.SignoffByName, Comment: signoff.Comment, CreatedAt: signoff.CreatedAt, UpdatedAt: signoff.UpdatedAt}
}

func BuildRiskSignoffSummary(scenario model.RolloverScenario, affected []algorithm.AffectedService, currentServices []model.DependentService, signoffs []model.ScenarioRiskSignoff, currentHash string) RiskSignoffSummary {
	summary := RiskSignoffSummary{CurrentHash: currentHash, InputChanged: currentHash != scenario.InputHash, Requirements: []CriticalServiceRequirement{}}
	serviceByID := map[uint]model.DependentService{}
	for _, service := range currentServices {
		serviceByID[service.ID] = service
	}
	signoffByService := map[uint]model.ScenarioRiskSignoff{}
	for _, signoff := range signoffs {
		signoffByService[signoff.ServiceID] = signoff
	}
	seen := map[uint]bool{}
	for _, affectedService := range affected {
		if affectedService.Criticality != "critical" || seen[affectedService.ServiceID] {
			continue
		}
		seen[affectedService.ServiceID] = true
		requirement := CriticalServiceRequirement{ServiceID: affectedService.ServiceID, ServiceCode: affectedService.ServiceCode, ServiceName: affectedService.ServiceName, OwnerTeam: affectedService.OwnerTeam, Criticality: affectedService.Criticality, Status: "pending"}
		if current, exists := serviceByID[affectedService.ServiceID]; exists {
			requirement.CurrentTeam = current.OwnerTeam
		}
		if signoff, exists := signoffByService[affectedService.ServiceID]; exists {
			response := NewRiskSignoffResponse(signoff)
			requirement.Signoff = &response
			requirement.Status = "signed"
			requirement.InvalidReason = validateRiskSignoff(scenario, signoff, affectedService, serviceByID[affectedService.ServiceID], summary.InputChanged)
			if requirement.InvalidReason != "" {
				requirement.Status = "invalid"
			}
		} else {
			requirement.InvalidReason = "等待责任团队负责人签收风险"
			if summary.InputChanged {
				requirement.InvalidReason = "冻结输入已经变化，旧推演结果需重新运行"
			} else if current, exists := serviceByID[affectedService.ServiceID]; !exists {
				requirement.InvalidReason = "当前服务台账中找不到该关键服务"
			} else if current.ServiceState != "active" {
				requirement.InvalidReason = "该关键服务当前已停用，请重新运行冻结推演"
			}
		}
		summary.Requirements = append(summary.Requirements, requirement)
	}
	summary.RequiredCount = len(summary.Requirements)
	for _, requirement := range summary.Requirements {
		if requirement.Status == "signed" {
			summary.SignedCount++
		}
	}
	summary.Ready = summary.RequiredCount == summary.SignedCount && !summary.InputChanged
	return summary
}

func validateRiskSignoff(scenario model.RolloverScenario, signoff model.ScenarioRiskSignoff, affected algorithm.AffectedService, current model.DependentService, inputChanged bool) string {
	if signoff.InputHash != scenario.InputHash {
		return "签收绑定的输入哈希与当前冻结场景不一致"
	}
	if inputChanged {
		return "冻结输入已经变化，签收已失效"
	}
	if signoff.OwnerTeam != affected.OwnerTeam {
		return "签收团队与冻结快照中的责任团队不一致"
	}
	if current.ID == 0 {
		return "当前服务台账中找不到该关键服务"
	}
	if current.OwnerTeam != signoff.OwnerTeam {
		return "服务责任团队已变更，需要新团队重新签收"
	}
	if current.ServiceState != "active" {
		return "该关键服务当前已停用，请重新运行冻结推演"
	}
	return ""
}
