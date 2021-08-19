package ssa

import "database/sql"

type KeyUsageService struct {
	db                  *sql.DB
	bindKeyStmnt        *sql.Stmt
	getPasswordStmnt    *sql.Stmt
	keyLifecycleService KeyLifeCycleManagementService
}

func (s KeyUsageService) Bind(password string) (key *Key, err error) {
	return &Key{}, nil
}

func (s KeyUsageService) Sign(keyId string, hashedPassword string) (signature []byte, err error)
