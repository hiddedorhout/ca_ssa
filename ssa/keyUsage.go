package ssa

import (
	"crypto/x509/pkix"
	"database/sql"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type KeyUsageService struct {
	db                  *sql.DB
	bindKeyStmnt        *sql.Stmt
	getPasswordStmnt    *sql.Stmt
	keyLifecycleService KeyLifeCycleManagementService
}

var (
	rsaEncryptionOid           = []int{1, 2, 840, 113549, 1, 1, 1}
	sha256HashAlgoOid          = []int{2, 16, 840, 1, 101, 3, 4, 2, 1}
	sha256WithRSAEncryptionOid = []int{1, 2, 840, 113549, 1, 1, 11}
)

func CreateKeyUsageService(keyLifecycleService *KeyLifeCycleManagementService, db *sql.DB) (keyUsageServe *KeyUsageService, err error) {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS keyBindings (
		keyId TEXT NOT NULL,
		passwordDigest TEXT NOT NULL,
		UNIQUE(keyId) ON CONFLICT FAIL
	)`); err != nil {
		return nil, err
	}

	bindKeyStmnt, err := db.Prepare(`INSERT INTO keyBindings
	(keyId, passwordDigest) values (?,?)`)
	if err != nil {
		return nil, err
	}

	getPasswordStmnt, err := db.Prepare(`SELECT 
	keyId, passwordDigest FROM keyBindings WHERE passwordDigest=?`)
	if err != nil {
		return nil, err
	}

	return &KeyUsageService{
		db:                  db,
		bindKeyStmnt:        bindKeyStmnt,
		getPasswordStmnt:    getPasswordStmnt,
		keyLifecycleService: *keyLifecycleService,
	}, nil
}

func (s KeyUsageService) CreateAndBind(password string) (key *Key, err error) {
	pwd, err := hashAndSalt([]byte(password))
	if err != nil {
		return nil, err
	}

	keyPair, err := s.keyLifecycleService.CreateKeyPair()
	if err != nil {
		return nil, err
	}

	if _, err := s.bindKeyStmnt.Exec(keyPair.KeyId, pwd); err != nil {
		return nil, err
	}

	return keyPair, nil
}

func hashAndSalt(pwd []byte) (encryptedPwd *string, err error) {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	encrpwd := string(hash)

	return &encrpwd, nil
}

func comparePwd(hashedPwd, plainPwd []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedPwd, plainPwd)
	if err != nil {
		return false
	}
	return true
}

type SignInfo struct {
	HashAlgo pkix.AlgorithmIdentifier
	SignAlgo pkix.AlgorithmIdentifier
}

func (s KeyUsageService) Sign(keyId string, hashedPassword string, tbsData []byte, signInfo SignInfo) (signature *[]byte, err error) {
	if (signInfo.SignAlgo.Algorithm.Equal(rsaEncryptionOid) && signInfo.HashAlgo.Algorithm.Equal(sha256HashAlgoOid)) ||
		signInfo.SignAlgo.Algorithm.Equal(sha256WithRSAEncryptionOid) {
		return s.keyLifecycleService.Sign(keyId, tbsData)
	} else {
		return nil, errors.New("Unsuported signing/ hash algorithm")
	}
}
