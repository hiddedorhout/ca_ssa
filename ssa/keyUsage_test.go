package ssa

import (
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"golang.org/x/crypto/bcrypt"
)

type mockKeyLifeCycleManagementService struct{}

var createKeyPairMock func() (key *Key, err error)

func (m mockKeyLifeCycleManagementService) CreateKeyPair() (key *Key, err error) {
	return createKeyPairMock()
}

var signMock func(keyId string, hash []byte) (signatureValue *[]byte, err error)

func (m mockKeyLifeCycleManagementService) Sign(keyId string, hash []byte) (signatureValue *[]byte, err error) {
	return signMock(keyId, hash)
}

var suspendKeyMock func(keyId string) error

func (m mockKeyLifeCycleManagementService) SuspendKey(keyId string) error {
	return suspendKeyMock(keyId)
}

func TestKeyUsageService(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS keyBindings").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectPrepare("INSERT INTO keyBindings")
	mock.ExpectPrepare("SELECT passwordDigest FROM keyBindings")

	var klms KeyLifeCycleManagement

	klms = mockKeyLifeCycleManagementService{}

	keyUsageService, err := CreateKeyUsageService(&klms, db)
	if err != nil {
		t.Fatal(err)
	}

	password := "password"
	testPkey, err := createRSAKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectExec("INSERT INTO keyBindings").WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	createKeyPairMock = func() (key *Key, err error) {
		return &Key{
			KeyId:     "keyId",
			PublicKey: &testPkey.PublicKey,
		}, nil
	}

	key, err := keyUsageService.CreateAndBind(password)
	if err != nil {
		t.Fatal(err)
	}

	if !testPkey.PublicKey.Equal(key.PublicKey) {
		t.Fatal(errors.New("TestKey was not equal to service key response"))
	}

	mockKeyId := "keyId"
	tbsd := []byte("tbs")
	signIfo := SignInfo{
		SignAlgo: pkix.AlgorithmIdentifier{Algorithm: []int{1, 2, 840, 113549, 1, 1, 11}},
	}

	signMock = func(keyId string, hash []byte) (signatureValue *[]byte, err error) {
		signature := []byte("signature")
		return &signature, nil
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

	mock.ExpectQuery("SELECT passwordDigest FROM keyBindings").WithArgs(mockKeyId).
		WillReturnRows(sqlmock.NewRows([]string{"passwordDigest"}).AddRow(string(hashedPassword)))

	if _, err := keyUsageService.Sign(mockKeyId, password, tbsd, signIfo); err != nil {
		t.Fatal(err)
	}

}
