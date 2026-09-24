package repository

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
	"pki-certificate-rollover-impact/backend/internal/model"
)

type RiskSignoffRepository interface {
	ListByScenario(ctx context.Context, scenarioID uint) ([]model.ScenarioRiskSignoff, error)
	ListByScenarioIDs(ctx context.Context, scenarioIDs []uint) (map[uint][]model.ScenarioRiskSignoff, error)
	FindByScenarioService(ctx context.Context, scenarioID, serviceID uint) (model.ScenarioRiskSignoff, error)
	Upsert(ctx context.Context, signoff *model.ScenarioRiskSignoff) error
}

type riskSignoffRepository struct{ db *gorm.DB }

func NewRiskSignoffRepository(db *gorm.DB) RiskSignoffRepository {
	return &riskSignoffRepository{db: db}
}

func (r *riskSignoffRepository) ListByScenario(ctx context.Context, scenarioID uint) ([]model.ScenarioRiskSignoff, error) {
	signoffs := []model.ScenarioRiskSignoff{}
	if err := scopedDB(ctx, r.db).Where("scenario_id = ?", scenarioID).Order("service_id ASC").Find(&signoffs).Error; err != nil {
		return nil, fmt.Errorf("list risk signoffs for scenario %d: %w", scenarioID, err)
	}
	return signoffs, nil
}

func (r *riskSignoffRepository) ListByScenarioIDs(ctx context.Context, scenarioIDs []uint) (map[uint][]model.ScenarioRiskSignoff, error) {
	result := map[uint][]model.ScenarioRiskSignoff{}
	if len(scenarioIDs) == 0 {
		return result, nil
	}
	signoffs := []model.ScenarioRiskSignoff{}
	if err := scopedDB(ctx, r.db).Where("scenario_id IN ?", scenarioIDs).Order("scenario_id ASC, service_id ASC").Find(&signoffs).Error; err != nil {
		return nil, fmt.Errorf("list risk signoffs: %w", err)
	}
	for _, signoff := range signoffs {
		result[signoff.ScenarioID] = append(result[signoff.ScenarioID], signoff)
	}
	return result, nil
}

func (r *riskSignoffRepository) FindByScenarioService(ctx context.Context, scenarioID, serviceID uint) (model.ScenarioRiskSignoff, error) {
	var signoff model.ScenarioRiskSignoff
	if err := scopedDB(ctx, r.db).Where("scenario_id = ? AND service_id = ?", scenarioID, serviceID).First(&signoff).Error; err != nil {
		return model.ScenarioRiskSignoff{}, fmt.Errorf("find risk signoff: %w", err)
	}
	return signoff, nil
}

func (r *riskSignoffRepository) Upsert(ctx context.Context, signoff *model.ScenarioRiskSignoff) error {
	db := scopedDB(ctx, r.db)
	var existing model.ScenarioRiskSignoff
	err := db.Where("scenario_id = ? AND service_id = ?", signoff.ScenarioID, signoff.ServiceID).First(&existing).Error
	if err == nil {
		signoff.ID = existing.ID
		signoff.CreatedAt = existing.CreatedAt
		signoff.UpdatedAt = time.Now().UTC()
		if updateErr := db.Model(&existing).Updates(map[string]any{
			"service_code":    signoff.ServiceCode,
			"owner_team":      signoff.OwnerTeam,
			"input_hash":      signoff.InputHash,
			"signoff_by":      signoff.SignoffBy,
			"signoff_by_name": signoff.SignoffByName,
			"comment":         signoff.Comment,
			"updated_at":      signoff.UpdatedAt,
		}).Error; updateErr != nil {
			return fmt.Errorf("update risk signoff: %w", updateErr)
		}
		return nil
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("find risk signoff before upsert: %w", err)
	}
	signoff.CreatedAt = time.Now().UTC()
	signoff.UpdatedAt = signoff.CreatedAt
	if createErr := db.Create(signoff).Error; createErr != nil {
		return fmt.Errorf("create risk signoff: %w", createErr)
	}
	return nil
}
