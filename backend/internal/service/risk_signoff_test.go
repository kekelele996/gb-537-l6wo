package service

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"gorm.io/gorm"

	"pki-certificate-rollover-impact/backend/internal/algorithm"
	"pki-certificate-rollover-impact/backend/internal/constants"
	"pki-certificate-rollover-impact/backend/internal/dto"
	"pki-certificate-rollover-impact/backend/internal/model"
	"pki-certificate-rollover-impact/backend/internal/repository"
	"pki-certificate-rollover-impact/backend/internal/util"
)

func riskSignoffFixture(t *testing.T, db *gorm.DB, state string) (model.RolloverScenario, model.DependentService) {
	t.Helper()
	now := time.Date(2032, 5, 2, 9, 0, 0, 0, time.UTC)
	dependent := model.DependentService{ServiceCode: "CRITICAL-PAYMENTS", Name: "Critical Payments API", OwnerTeam: "Payments", Environment: "production", ChainID: 1, ClientTrustRefsJSON: "[1]", Protocol: "mtls", Criticality: "critical", DependencyEdgesJSON: "[]", ServiceState: "active", CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&dependent).Error; err != nil {
		t.Fatal(err)
	}
	affected, err := encode([]algorithm.AffectedService{{ServiceID: dependent.ID, ServiceCode: dependent.ServiceCode, ServiceName: dependent.Name, OwnerTeam: dependent.OwnerTeam, Criticality: "critical", At: now, Reason: "trust path broken"}})
	if err != nil {
		t.Fatal(err)
	}
	scenario := minimalScenario(t, db, "risk-signoff", "risk-hash", "risk-key", state, 7, 0)
	scenario.AffectedServicesJSON = affected
	return persistScenario(t, db, scenario), dependent
}

func newRiskSignoffService(db *gorm.DB) *RolloverScenarioService {
	return NewRolloverScenarioService(
		repository.NewRolloverScenarioRepository(db),
		nil,
		nil,
		repository.NewDependentServiceRepository(db),
		repository.NewAuditRepository(db),
		repository.NewTransactionManager(db),
	)
}

func assertAPIError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var apiErr *util.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != status || apiErr.Code != code {
		t.Fatalf("got %#v, want %d %s", err, status, code)
	}
}

func TestReadyRequiresValidCriticalServiceRiskSignoff(t *testing.T) {
	db := newScenarioTestDB(t)
	scenario, dependent := riskSignoffFixture(t, db, "simulated")
	scenarioService := newRiskSignoffService(db)
	owner := util.Actor{UserID: 20, Username: "payments-lead", DisplayName: "Payments Lead", Team: "Payments", Role: string(constants.RoleServiceOwner)}
	operator := util.Actor{UserID: 7, Username: "operator", DisplayName: "PKI Operations Lead", Team: "PKI Platform", Role: string(constants.RolePKIOperator)}
	toReady := dto.RolloverScenarioTransitionRequest{ToState: string(constants.ScenarioReady)}

	_, err := scenarioService.Transition(context.Background(), scenario.ID, toReady, operator, "request-missing-signoff")
	assertAPIError(t, err, http.StatusConflict, util.CodeRiskSignoff)

	signed, err := scenarioService.SignoffRisk(context.Background(), scenario.ID, dto.ScenarioRiskSignoffRequest{ServiceID: dependent.ID, Comment: "accepted"}, owner, "request-signoff")
	_ = signed
	if err != nil {
		t.Fatal(err)
	}
	if signed.ID == 0 {
		t.Fatal("expected scenario response")
	}
	if len(signed.RiskSignoffs.RequiredCriticalServices) != 1 || !signed.RiskSignoffs.Ready {
		t.Fatalf("risk signoff summary not ready: %+v", signed.RiskSignoffs)
	}

	ready, err := scenarioService.Transition(context.Background(), scenario.ID, toReady, operator, "request-ready")
	if err != nil {
		t.Fatal(err)
	}
	if ready.ScenarioState != string(constants.ScenarioReady) {
		t.Fatalf("state = %s, want ready", ready.ScenarioState)
	}
}

func TestRiskSignoffRejectsCrossTeamAndUnauthorizedRole(t *testing.T) {
	db := newScenarioTestDB(t)
	scenario, _ := riskSignoffFixture(t, db, "simulated")
	scenarioService := newRiskSignoffService(db)
	crossTeam := util.Actor{UserID: 21, Username: "identity-lead", Team: "Identity", Role: string(constants.RoleServiceOwner)}
	_, err := scenarioService.SignoffRisk(context.Background(), scenario.ID, dto.ScenarioRiskSignoffRequest{ServiceID: 1}, crossTeam, "request-cross-team")
	assertAPIError(t, err, http.StatusForbidden, util.CodeForbidden)

	admin := util.Actor{UserID: 1, Username: "admin", Team: "PKI Platform", Role: string(constants.RoleAdmin)}
	_, err = scenarioService.SignoffRisk(context.Background(), scenario.ID, dto.ScenarioRiskSignoffRequest{ServiceID: 1}, admin, "request-admin")
	assertAPIError(t, err, http.StatusForbidden, util.CodeForbidden)
}

func TestRiskSignoffIsUpsertAndStaleHashBlocksReady(t *testing.T) {
	db := newScenarioTestDB(t)
	scenario, dependent := riskSignoffFixture(t, db, "simulated")
	scenarioService := newRiskSignoffService(db)
	owner := util.Actor{UserID: 20, Username: "payments-lead", Team: "Payments", Role: string(constants.RoleServiceOwner)}
	operator := util.Actor{UserID: 7, Username: "operator", Team: "PKI Platform", Role: string(constants.RolePKIOperator)}
	request := dto.ScenarioRiskSignoffRequest{ServiceID: dependent.ID, Comment: "first acceptance"}
	if _, err := scenarioService.SignoffRisk(context.Background(), scenario.ID, request, owner, "request-first"); err != nil {
		t.Fatal(err)
	}
	request.Comment = "updated acceptance"
	if _, err := scenarioService.SignoffRisk(context.Background(), scenario.ID, request, owner, "request-second"); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.Model(&model.ScenarioRiskSignoff{}).Where("scenario_id = ? AND service_id = ?", scenario.ID, dependent.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("signoff count = %d, want one upserted row", count)
	}
	if err := db.Model(&model.RolloverScenario{}).Where("id = ?", scenario.ID).Update("input_hash", "changed-hash").Error; err != nil {
		t.Fatal(err)
	}
	_, err := scenarioService.Transition(context.Background(), scenario.ID, dto.RolloverScenarioTransitionRequest{ToState: string(constants.ScenarioReady)}, operator, "request-stale-hash")
	assertAPIError(t, err, http.StatusConflict, util.CodeRiskSignoff)
}

func TestRiskSignoffInvalidatesWhenServiceOwnershipChanges(t *testing.T) {
	db := newScenarioTestDB(t)
	scenario, dependent := riskSignoffFixture(t, db, "simulated")
	scenarioService := newRiskSignoffService(db)
	owner := util.Actor{UserID: 20, Username: "payments-lead", Team: "Payments", Role: string(constants.RoleServiceOwner)}
	operator := util.Actor{UserID: 7, Username: "operator", Team: "PKI Platform", Role: string(constants.RolePKIOperator)}
	if _, err := scenarioService.SignoffRisk(context.Background(), scenario.ID, dto.ScenarioRiskSignoffRequest{ServiceID: dependent.ID}, owner, "request-before-transfer"); err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.DependentService{}).Where("id = ?", dependent.ID).Update("owner_team", "Identity").Error; err != nil {
		t.Fatal(err)
	}
	_, err := scenarioService.Transition(context.Background(), scenario.ID, dto.RolloverScenarioTransitionRequest{ToState: string(constants.ScenarioReady)}, operator, "request-transfer")
	assertAPIError(t, err, http.StatusConflict, util.CodeRiskSignoff)

	summary, err := scenarioService.Get(context.Background(), scenario.ID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.RiskSignoffs.Ready || len(summary.RiskSignoffs.InvalidServiceIDs) != 1 {
		t.Fatalf("expected invalid signoff summary: %+v", summary.RiskSignoffs)
	}
	if summary.RiskSignoffs.RequiredCriticalServices[0].InvalidReason == "" {
		t.Fatal("expected an invalid reason on scenario page payload")
	}
}
