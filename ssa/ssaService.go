package ssa

import "database/sql"

type SsaService struct {
	db                            *sql.DB
	keyLifeCycleManagementService *KeyLifeCycleManagement
	keyUsageService               *KeyUsage
}

func NewSsaService(db *sql.DB) (ssaService *SsaService, err error) {

	var klms KeyLifeCycleManagement
	var kus KeyUsage

	keyLifecycleService, err := CreateKeyLifeCycleManagementService(db)
	if err != nil {
		return nil, err
	}
	klms = keyLifecycleService

	keyUsageService, err := CreateKeyUsageService(&klms, db)
	if err != nil {
		return nil, err
	}
	kus = keyUsageService

	return &SsaService{
		db:                            db,
		keyLifeCycleManagementService: &klms,
		keyUsageService:               &kus,
	}, nil
}
