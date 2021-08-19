package ssa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
)

type KeyLifeCycleManagementService struct {
	db            *sql.DB
	storeKeyStmnt *sql.Stmt
	getKeyStmnt   *sql.Stmt
}

func CreateKeyLifeCycleManagementService(db *sql.DB) (keyCreationService *KeyLifeCycleManagementService, err error) {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS keystore (
		id TEXT PRIMARY KEY,
		key TEXT NOT NULL,
		active BOOLEAN NOT NULL CHECK (active IN (0, 1)),
		UNIQUE(id) ON CONFLICT FAIL
	)`); err != nil {
		return nil, err
	}

	storeKeyStmnt, err := db.Prepare(`INSERT INTO keystore
	(id, key, active) values (?,?,1)`)
	if err != nil {
		return nil, err
	}

	getKeyStmnt, err := db.Prepare(`SELECT 
	key FROM keystore WHERE id=? AND active=1`)
	if err != nil {
		return nil, err
	}

	return &KeyLifeCycleManagementService{
		db:            db,
		storeKeyStmnt: storeKeyStmnt,
		getKeyStmnt:   getKeyStmnt,
	}, nil
}

type Key struct {
	KeyId     string
	PublicKey *rsa.PublicKey
}

func (s KeyLifeCycleManagementService) CreateKeyPair() (key *Key, err error) {
	privateKey, err := createRSAKeyPair(2048)
	if err != nil {
		return nil, err
	}
	keyId, err := createKeyId(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	if _, err := s.storeKeyStmnt.Exec(keyId, encodePrivateKey(privateKey)); err != nil {
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

func getPublicKey(privateKey *rsa.PrivateKey) *rsa.PublicKey {
	publicKey := privateKey.Public().(*rsa.PublicKey)
	return publicKey
}
