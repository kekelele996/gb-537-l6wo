package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"pki-certificate-rollover-impact/backend/internal/algorithm"
	"pki-certificate-rollover-impact/backend/internal/constants"
	"pki-certificate-rollover-impact/backend/internal/dto"
	"pki-certificate-rollover-impact/backend/internal/model"
	"pki-certificate-rollover-impact/backend/internal/repository"
	"pki-certificate-rollover-impact/backend/internal/util"
)

type riskGateFixture struct {
	db        *gorm.DB
	svc       *RolloverScenarioService
	scenario  model.RolloverScenario
	dependent model.DependentService
	owner     model.User
}

func newRiskGateFixture(t *testing.T, team string) riskGateFixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	migrateErr := db.AutoMigrate(&model.User{}, &model.TrustAnchor{}, &model.CertificateChain{}, &model.DependentService{}, &model.RolloverScenario{}, &model.ScenarioRiskSignoff{}, &model.AuditLog{})
	if migrateErr != nil {
		t.Fatal(migrateErr)
	}
	now := time.Date(2031, 3, 4, 9, 0, 0, 0, time.UTC)
	anchors := []model.TrustAnchor{
		{AnchorCode: "RISK-OLD", SubjectDN: "CN=old", SerialNumber: "1", FingerprintSHA256: "1111111111111111111111111111111111111111111111111111111111111111", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), KeyAlgorithm: "ECDSA", CertificateState: "valid", PemRedacted: "old-cert", CreatedAt: now, UpdatedAt: now},
		{AnchorCode: "RISK-NEW", SubjectDN: "CN=new", SerialNumber: "2", FingerprintSHA256: "2222222222222222222222222222222222222222222222222222222222222222", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), KeyAlgorithm: "ECDSA", CertificateState: "valid", PemRedacted: "new-cert", CreatedAt: now, UpdatedAt: now},
	}
	if err := db.Create(&anchors).Error; err != nil {
		t.Fatal(err)
	}
	chain := model.CertificateChain{ChainCode: "RISK-CHAIN", TrustAnchorID: anchors[0].ID, LeafSubject: "CN=payments", CertificateRefsJSON: "[]", ChainFingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", ValidFrom: now.Add(-time.Hour), ValidTo: now.Add(24 * time.Hour), ValidationResult: `{"valid":true}`, ChainState: string(constants.ChainValidated), SourceChecksum: "source", PublicChainPEM: "chain", CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&chain).Error; err != nil {
		t.Fatal(err)
	}
	trustJSON, _ := json.Marshal([]uint{anchors[0].ID, anchors[1].ID})
	dependent := model.DependentService{ServiceCode: "RISK-PAYMENTS", Name: "Risk Payments API", OwnerTeam: team, Environment: "production", ChainID: chain.ID, ClientTrustRefsJSON: string(trustJSON), Protocol: "mtls", Criticality: "critical", DependencyEdgesJSON: "[]", ServiceState: string(constants.ServiceActive), CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&dependent).Error; err != nil {
		t.Fatal(err)
	}
	owner := model.User{Username: "risk-owner-" + team, DisplayName: "Risk Owner", Team: team, PasswordHash: "x", Role: string(constants.RoleServiceOwner), Active: true, CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&owner).Error; err != nil {
		t.Fatal(err)
	}
	snapshot := algorithm.NewSnapshot(
		algorithm.ScenarioConfig{Name: "risk gate", OldAnchorID: anchors[0].ID, NewAnchorID: anchors[1].ID, OverlapStart: now.Add(time.Hour), OverlapEnd: now.Add(2 * time.Hour), CandidateChainIDs: []uint{chain.ID}, SimulationTime: now.Add(90 * time.Minute)},
		[]algorithm.AnchorSnapshot{{ID: anchors[0].ID, Code: anchors[0].AnchorCode, State: "valid", NotBefore: anchors[0].NotBefore, NotAfter: anchors[0].NotAfter}, {ID: anchors[1].ID, Code: anchors[1].AnchorCode, State: "valid", NotBefore: anchors[1].NotBefore, NotAfter: anchors[1].NotAfter}},
		[]algorithm.ChainSnapshot{{ID: chain.ID, Code: chain.ChainCode, AnchorID: chain.TrustAnchorID, LeafSubject: chain.LeafSubject, ValidFrom: chain.ValidFrom, ValidTo: chain.ValidTo, State: chain.ChainState, ValidationValid: true}},
		[]algorithm.ServiceSnapshot{{ID: dependent.ID, Code: dependent.ServiceCode, Name: dependent.Name, OwnerTeam: dependent.OwnerTeam, ChainID: dependent.ChainID, TrustAnchorIDs: []uint{anchors[0].ID, anchors[1].ID}, Criticality: dependent.Criticality, State: dependent.ServiceState}},
	)
	hash, err := snapshot.Hash()
	if err != nil {
		t.Fatal(err)
	}
	snapshotJSON, _ := snapshot.Canonical()
	affectedJSON, _ := json.Marshal([]algorithm.AffectedService{{ServiceID: dependent.ID, ServiceCode: dependent.ServiceCode, ServiceName: dependent.Name, OwnerTeam: dependent.OwnerTeam, Criticality: "critical", At: now, Reason: "trust set does not include replacement anchor"}})
	candidateJSON, _ := json.Marshal([]uint{chain.ID})
	scenario := model.RolloverScenario{Name: "risk gate", OldAnchorID: anchors[0].ID, NewAnchorID: anchors[1].ID, OverlapStart: now.Add(time.Hour), OverlapEnd: now.Add(2 * time.Hour), CandidateChainIDs: string(candidateJSON), AlgorithmVersion: algorithm.Version, InputHash: hash, InputSnapshot: snapshotJSON, SimulationTime: now.Add(90 * time.Minute), AffectedServicesJSON: string(affectedJSON), BrokenPathsJSON: "[]", PathEvidenceJSON: "[]", ScenarioState: string(constants.ScenarioSimulated), Explanation: "critical impact", CreatedBy: owner.ID + 100, CreatedByName: "operator", CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&scenario).Error; err != nil {
		t.Fatal(err)
	}
	scenarioService := NewRolloverScenarioService(
		repository.NewRolloverScenarioRepository(db),
		repository.NewTrustAnchorRepository(db),
		repository.NewCertificateChainRepository(db),
		repository.NewDependentServiceRepository(db),
		repository.NewAuditRepository(db),
		repository.NewRiskSignoffRepository(db),
		repository.NewUserRepository(db),
		repository.NewTransactionManager(db),
	)
	return riskGateFixture{db: db, svc: scenarioService, scenario: scenario, dependent: dependent, owner: owner}
}

func actorFor(user model.User) util.Actor {
	return util.Actor{UserID: user.ID, Username: user.Username, Team: user.Team, Role: user.Role}
}

func assertAPIError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var apiErr *util.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != status || apiErr.Code != code {
		t.Fatalf("got %#v, want %d %s", err, status, code)
	}
}

func TestReadyRequiresEveryCriticalServiceSignoff(t *testing.T) {
	fixture := newRiskGateFixture(t, "Payments Platform")
	_, err := fixture.svc.Transition(context.Background(), fixture.scenario.ID, dto.RolloverScenarioTransitionRequest{ToState: string(constants.ScenarioReady)}, util.Actor{UserID: 99, Username: "operator", Role: string(constants.RolePKIOperator)}, "request-missing-signoff")
	assertAPIError(t, err, http.StatusConflict, util.CodeStateTransition)

	response, err := fixture.svc.Get(context.Background(), fixture.scenario.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.RiskSignoffs.Requirements) != 1 || response.RiskSignoffs.Requirements[0].Status != "pending" {
		t.Fatalf("expected one pending critical service, got %+v", response.RiskSignoffs)
	}
	if response.RiskSignoffs.Ready {
		t.Fatal("scenario must not be ready before risk signoff")
	}
}

func TestOwningTeamOwnerSignoffIsIdempotentAndUnlocksReady(t *testing.T) {
	fixture := newRiskGateFixture(t, "Payments Platform")
	first, err := fixture.svc.SignRisk(context.Background(), fixture.scenario.ID, dto.RiskSignoffRequest{ServiceID: fixture.dependent.ID}, actorFor(fixture.owner), "request-signoff")
	if err != nil {
		t.Fatal(err)
	}
	if first.RiskSignoffs.SignedCount != 1 || !first.RiskSignoffs.Ready {
		t.Fatalf("signoff summary not complete: %+v", first.RiskSignoffs)
	}
	if _, err := fixture.svc.SignRisk(context.Background(), fixture.scenario.ID, dto.RiskSignoffRequest{ServiceID: fixture.dependent.ID, Comment: "再次确认"}, actorFor(fixture.owner), "request-repeat-signoff"); err != nil {
		t.Fatalf("repeat signoff should update the same record: %v", err)
	}
	var count int64
	if err := fixture.db.Model(&model.ScenarioRiskSignoff{}).Where("scenario_id = ? AND service_id = ?", fixture.scenario.ID, fixture.dependent.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected one signoff per scenario/service, got %d", count)
	}
	transitioned, err := fixture.svc.Transition(context.Background(), fixture.scenario.ID, dto.RolloverScenarioTransitionRequest{ToState: string(constants.ScenarioReady)}, util.Actor{UserID: 99, Username: "operator", Role: string(constants.RolePKIOperator)}, "request-ready")
	if err != nil {
		t.Fatal(err)
	}
	if transitioned.ScenarioState != string(constants.ScenarioReady) {
		t.Fatalf("state = %s, want ready", transitioned.ScenarioState)
	}
}

func TestRiskSignoffRejectsCrossTeamOwner(t *testing.T) {
	fixture := newRiskGateFixture(t, "Payments Platform")
	other := model.User{Username: "identity-owner", DisplayName: "Identity Owner", Team: "Identity Platform", PasswordHash: "x", Role: string(constants.RoleServiceOwner), Active: true}
	if err := fixture.db.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	_, err := fixture.svc.SignRisk(context.Background(), fixture.scenario.ID, dto.RiskSignoffRequest{ServiceID: fixture.dependent.ID}, actorFor(other), "request-cross-team")
	assertAPIError(t, err, http.StatusForbidden, util.CodeForbidden)
}

func TestRiskSignoffRejectedWhenFrozenInputChanged(t *testing.T) {
	fixture := newRiskGateFixture(t, "Payments Platform")
	trustJSON, _ := json.Marshal([]uint{fixture.scenario.OldAnchorID})
	if err := fixture.db.Model(&model.DependentService{}).Where("id = ?", fixture.dependent.ID).Update("client_trust_refs_json", string(trustJSON)).Error; err != nil {
		t.Fatal(err)
	}
	_, err := fixture.svc.SignRisk(context.Background(), fixture.scenario.ID, dto.RiskSignoffRequest{ServiceID: fixture.dependent.ID}, actorFor(fixture.owner), "request-stale-input")
	assertAPIError(t, err, http.StatusConflict, util.CodeStateTransition)

	response, getErr := fixture.svc.Get(context.Background(), fixture.scenario.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if !response.RiskSignoffs.InputChanged || response.RiskSignoffs.Ready {
		t.Fatalf("expected stale frozen input, got %+v", response.RiskSignoffs)
	}
}
