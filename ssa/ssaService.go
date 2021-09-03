package ssa

import (
	"database/sql"
	"fmt"
)

type SsaService struct {
	db                            *sql.DB
	keyLifeCycleManagementService *KeyLifeCycleManagement
	keyUsageService               *KeyUsage
	sessionManagementService      *SessionManagement
	baseUrl                       string
}

func NewSsaService(db *sql.DB, baseUrl, port string) (ssaService *SsaService, err error) {

	var klms KeyLifeCycleManagement
	var kus KeyUsage
	var sms SessionManagement

	sessionManagementService, err := CreateSessionService(db)
	if err != nil {
		return nil, err
	}
	sms = sessionManagementService

	keyLifecycleService, err := CreateKeyLifeCycleManagementService(db)
	if err != nil {
		return nil, err
	}
	klms = keyLifecycleService

	keyUsageService, err := CreateKeyUsageService(&sms, &klms, db)
	if err != nil {
		return nil, err
	}
	kus = keyUsageService

	var optionalPort string
	if port == "" {
		optionalPort = ""
	} else {
		optionalPort = fmt.Sprintf(":%s", port)
	}

	return &SsaService{
		db:                            db,
		keyLifeCycleManagementService: &klms,
		keyUsageService:               &kus,
		sessionManagementService:      &sms,
		baseUrl:                       fmt.Sprintf("%s%s", baseUrl, optionalPort),
	}, nil
}
