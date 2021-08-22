package ssa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"errors"
)

type KeyLifeCycleManagement interface {
	CreateKeyPair() (key *Key, err error)
	Sign(keyId string, hash []byte) (signatureValue *[]byte, err error)
	SuspendKey(keyId string) error
}

type KeyLifeCycleManagementService struct {
	db              *sql.DB
	storeKeyStmnt   *sql.Stmt
	getKeyStmnt     *sql.Stmt
	suspendKeyStmnt *sql.Stmt
}

func CreateKeyLifeCycleManagementService(db *sql.DB) (keyLifeCycleManagementService *KeyLifeCycleManagementService, err error) {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		key TEXT NOT NULL,
		keyType TEXT NOT NULL,
		active BOOLEAN NOT NULL CHECK (active IN (0, 1)),
		UNIQUE(id) ON CONFLICT FAIL
	)`); err != nil {
		return nil, err
	}

	storeKeyStmnt, err := db.Prepare(`INSERT INTO keys
	(id, key, keyType, active) values (?,?,?,1)`)
	if err != nil {
		return nil, err
	}

	getKeyStmnt, err := db.Prepare(`SELECT 
	key, keyType FROM keys WHERE id=? AND active=1`)
	if err != nil {
		return nil, err
	}

	suspendKeyStmnt, err := db.Prepare(`UPDATE 
	keys SET active=0 WHERE id=?`)
	if err != nil {
		return nil, err
	}

	return &KeyLifeCycleManagementService{
		db:              db,
		storeKeyStmnt:   storeKeyStmnt,
		getKeyStmnt:     getKeyStmnt,
		suspendKeyStmnt: suspendKeyStmnt,
	}, nil
}

type Key struct {
	KeyId     string
	PublicKey *rsa.PublicKey
}

func (s *KeyLifeCycleManagementService) CreateKeyPair() (key *Key, err error) {
	privateKey, err := createRSAKeyPair(2048)
	if err != nil {
		return nil, err
	}
	keyId, err := createKeyId(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	if _, err := s.storeKeyStmnt.Exec(keyId, encodePrivateKey(privateKey), "rsa"); err != nil {
		return nil, err
	}
	return &Key{
		KeyId:     *keyId,
		PublicKey: getPublicKey(privateKey),
	}, nil
}

func createRSAKeyPair(bits int) (keyPair *rsa.PrivateKey, err error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func createKeyId(publicKey *rsa.PublicKey) (keyIdentifier *string, er error) {
	bytes, err := asn1.Marshal(*publicKey)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write(bytes)
	digest := h.Sum(nil)

	identifier := base64.StdEncoding.EncodeToString(digest)
	return &identifier, nil
}

func encodePrivateKey(privateKey *rsa.PrivateKey) string {
	rawKey := x509.MarshalPKCS1PrivateKey(privateKey)
	return base64.StdEncoding.EncodeToString(rawKey)
}

func decodePrivateKey(encodedPrivateKey string) (key *rsa.PrivateKey, err error) {
	rawKey, err := base64.StdEncoding.DecodeString(encodedPrivateKey)
	if err != nil {
		return nil, err
	}
	pKey, err := x509.ParsePKCS1PrivateKey(rawKey)
	if err != nil {
		return nil, err
	}
	return pKey, nil
}

func getPublicKey(privateKey *rsa.PrivateKey) *rsa.PublicKey {
	publicKey := privateKey.Public().(*rsa.PublicKey)
	return publicKey
}

func (s *KeyLifeCycleManagementService) Sign(keyId string, hash []byte) (signatureValue *[]byte, err error) {

	var encodedKey string
	var keyType string
	if err := s.getKeyStmnt.QueryRow(keyId).Scan(&encodedKey, &keyType); err != nil {
		return nil, err
	}

	if keyType != "rsa" {
		return nil, errors.New("Unsupported key type")
	}

	pkey, err := decodePrivateKey(encodedKey)
	if err != nil {
		return nil, err
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, pkey, crypto.SHA256, hash)
	if err != nil {
		return nil, err
	}
	return &signature, nil
}

func (s KeyLifeCycleManagementService) SuspendKey(keyId string) error {
	if _, err := s.suspendKeyStmnt.Exec(keyId); err != nil {
		return err
	}
	return nil
}
