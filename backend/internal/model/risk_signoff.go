package model

import "time"

type ScenarioRiskSignoff struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	ScenarioID    uint      `gorm:"not null;uniqueIndex:idx_scenario_service_signoff,priority:1;index" json:"scenario_id"`
	ServiceID     uint      `gorm:"not null;uniqueIndex:idx_scenario_service_signoff,priority:2;index" json:"service_id"`
	ServiceCode   string    `gorm:"size:80;not null" json:"service_code"`
	OwnerTeam     string    `gorm:"size:160;not null;index" json:"owner_team"`
	InputHash     string    `gorm:"size:64;not null" json:"input_hash"`
	SignoffBy     uint      `gorm:"not null" json:"signoff_by"`
	SignoffByName string    `gorm:"size:80;not null" json:"signoff_by_name"`
	Comment       string    `gorm:"size:1000;not null" json:"comment"`
	CreatedAt     time.Time `gorm:"not null" json:"created_at"`
	UpdatedAt     time.Time `gorm:"not null" json:"updated_at"`
}
