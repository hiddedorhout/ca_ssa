package ssa

import (
	"crypto/sha256"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestKeyService(t *testing.T) {

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS keys").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectPrepare("INSERT INTO keys")
	mock.ExpectPrepare("SELECT key, keyType FROM keys")
	mock.ExpectPrepare("UPDATE keys SET")

	keyLifecycleService, err := CreateKeyLifeCycleManagementService(db)
	if err != nil {
		t.Fatal(err)
	}

	_, pkey, err := createMockKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectExec("INSERT INTO keys").WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "rsa").WillReturnResult(sqlmock.NewResult(1, 1))

	keyPair, err := keyLifecycleService.CreateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery("SELECT key, keyType FROM keys").WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"key", "keyType"}).AddRow(pkey, "rsa"))
	dtbs := hash([]byte("hello"))
	if _, err := keyLifecycleService.Sign(keyPair.KeyId, dtbs); err != nil {
		t.Fatal(err)
	}
}

func createMockKeyPair() (key *Key, pkey *string, err error) {
	keyPair, err := createRSAKeyPair(2048)
	if err != nil {
		return nil, nil, err
	}
	keyId, err := createKeyId(&keyPair.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	encoded := encodePrivateKey(keyPair)
	return &Key{
		KeyId:     *keyId,
		PublicKey: &keyPair.PublicKey,
	}, &encoded, nil
}

func hash(dtbs []byte) []byte {
	h := sha256.New()
	h.Write(dtbs)
	return h.Sum(nil)
}
