package ssa

import (
	"crypto/rsa"
	"crypto/x509/pkix"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type KeyUsage interface {
	CreateAndBind(password string) (user *User, err error)
	Sign(keyId string, hashedPassword string, tbsData []byte, signInfo SignInfo) (signature *[]byte, err error)
	GetKeyId(userId string) (keyId *string, err error)
}

type KeyUsageService struct {
	db                  *sql.DB
	bindKeyStmnt        *sql.Stmt
	getPasswordStmnt    *sql.Stmt
	getKeyIdStmnt       *sql.Stmt
	sessionService      *SessionManagement
	keyLifecycleService *KeyLifeCycleManagement
}

type User struct {
	UserId    string
	PublicKey *rsa.PublicKey
}

var (
	rsaEncryptionOid           = []int{1, 2, 840, 113549, 1, 1, 1}
	sha256HashAlgoOid          = []int{2, 16, 840, 1, 101, 3, 4, 2, 1}
	sha256WithRSAEncryptionOid = []int{1, 2, 840, 113549, 1, 1, 11}
)

func CreateKeyUsageService(keyLifeCycleManagementService *KeyLifeCycleManagement, db *sql.DB) (keyUsageService *KeyUsageService, err error) {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS keyBindings (
		userId TEXT NOT NULL,
		keyId TEXT NOT NULL,
		passwordDigest TEXT NOT NULL,
		UNIQUE(userId, keyId) ON CONFLICT FAIL
	)`); err != nil {
		return nil, err
	}

	bindKeyStmnt, err := db.Prepare(`INSERT INTO keyBindings
	(userId, keyId, passwordDigest) values (?, ?,?)`)
	if err != nil {
		return nil, err
	}

	getPasswordStmnt, err := db.Prepare(`SELECT 
	passwordDigest FROM keyBindings WHERE keyId=?`)
	if err != nil {
		return nil, err
	}

	getKeyIdStmnt, err := db.Prepare(`SELECT 
	keyId FROM keyBindings WHERE userId=?`)
	if err != nil {
		return nil, err
	}

	return &KeyUsageService{
		db:                  db,
		bindKeyStmnt:        bindKeyStmnt,
		getPasswordStmnt:    getPasswordStmnt,
		getKeyIdStmnt:       getKeyIdStmnt,
		keyLifecycleService: keyLifeCycleManagementService,
	}, nil
}

func (s *KeyUsageService) CreateAndBind(password string) (user *User, err error) {
	pwd, err := hashAndSalt([]byte(password))
	if err != nil {
		return nil, err
	}
	kls := *s.keyLifecycleService

	keyPair, err := kls.CreateKeyPair()
	if err != nil {
		return nil, err
	}

	userId := uuid.NewString()

	if _, err := s.bindKeyStmnt.Exec(userId, keyPair.KeyId, pwd); err != nil {
		return nil, err
	}

	return &User{
		UserId:    userId,
		PublicKey: keyPair.PublicKey,
	}, nil
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

func (s *KeyUsageService) Sign(keyId string, plainPwd string, tbsData []byte, signInfo SignInfo) (signature *[]byte, err error) {
	if (signInfo.SignAlgo.Algorithm.Equal(rsaEncryptionOid) && signInfo.HashAlgo.Algorithm.Equal(sha256HashAlgoOid)) ||
		signInfo.SignAlgo.Algorithm.Equal(sha256WithRSAEncryptionOid) {

		var encodedPwd string
		if err := s.getPasswordStmnt.QueryRow(keyId).Scan(&encodedPwd); err != nil {
			return nil, err
		}
		if comparePwd([]byte(encodedPwd), []byte(plainPwd)) {
			kls := *s.keyLifecycleService
			signature, err := kls.Sign(keyId, tbsData)
			if err != nil {
				return nil, err
			}
			return signature, nil
		} else {
			return nil, errors.New("Invalid credentials")
		}
	} else {
		return nil, errors.New("Unsuported signing/ hash algorithm")
	}
}

func (s *KeyUsageService) GetKeyId(userId string) (keyId *string, err error) {
	var key string
	if err := s.getKeyIdStmnt.QueryRow(userId).Scan(&key); err != nil {
		return nil, err
	}
	return &key, nil
}
