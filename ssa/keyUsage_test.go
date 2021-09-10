package ssa

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	sm "github.com/hiddedorhout/ca_ssa/session"
	"golang.org/x/crypto/bcrypt"
)

// KeyLiceCycleMock
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

var signCsrMock func(keyId string, template x509.CertificateRequest) (csr *[]byte, err error)

func (m mockKeyLifeCycleManagementService) SignCsr(keyId string, template x509.CertificateRequest) (csr *[]byte, err error) {
	return signCsrMock(keyId, template)
}

// SessionServiceMock
type mockSessionManagementService struct{}

var createSessionMock func(keyId string) (sessionId *string, err error)

func (sms mockSessionManagementService) CreateSession(keyId string) (sessionId *string, err error) {
	return createSessionMock(keyId)
}

var updateSessionMock func(sessionId string) error

func (sms mockSessionManagementService) UpdateSession(sessionId string, event sm.Event) error {
	return updateSessionMock(sessionId)
}

var terminaSessionMock func(sessionId, reason string) error

func (sms mockSessionManagementService) TerminateSession(sessionId, reason string) error {
	return terminaSessionMock(sessionId, reason)
}

var getSessionStateMock func(sessionId string) (sessionState *sm.SessionState, err error)

func (sms mockSessionManagementService) GetSessionState(sessionId string) (sessionState *sm.SessionState, err error) {
	return getSessionStateMock(sessionId)
}

// Test
func TestKeyUsageService(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS keyBindings").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectPrepare("INSERT INTO keyBindings")
	mock.ExpectPrepare("SELECT passwordDigest FROM keyBindings")
	mock.ExpectPrepare("SELECT keyId FROM keyBindings")

	var klms KeyLifeCycleManagement
	var sms sm.SessionManagement

	klms = mockKeyLifeCycleManagementService{}
	sms = mockSessionManagementService{}

	mockChannel := make(chan string)

	keyUsageService, err := CreateKeyUsageService(&sms, &klms, db, mockChannel)
	if err != nil {
		t.Fatal(err)
	}

	password := "password"
	testPkey, err := createRSAKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectExec("INSERT INTO keyBindings").WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	createKeyPairMock = func() (key *Key, err error) {
		return &Key{
			KeyId:     "keyId",
			PublicKey: &testPkey.PublicKey,
		}, nil
	}

	user, err := keyUsageService.CreateAndBind(password)
	if err != nil {
		t.Fatal(err)
	}

	if !testPkey.PublicKey.Equal(user.PublicKey) {
		t.Fatal(errors.New("TestKey was not equal to service key response"))
	}

	mockKeyId := "keyId"
	tbsd := []byte("tbs")
	signInfo := sm.SignInfo{
		SignAlgo: pkix.AlgorithmIdentifier{Algorithm: []int{1, 2, 840, 113549, 1, 1, 11}},
	}

	sessionId := "sessionId"
	getSessionStateMock = func(sessionId string) (sessionState *sm.SessionState, err error) {
		state := sm.SessionState{
			State: sm.SigningState{
				CurrentStateName: sm.SignatureRequestedName,
				UserId:           user.UserId,
				KeyId:            mockKeyId,
				Dtbsr:            tbsd,
				SignInfo:         signInfo,
				Terminated:       false,
			},
		}

		return &state, nil
	}
	updateSessionMock = func(sessionId string) error {
		return nil
	}

	sigMock := []byte("signature")

	signMock = func(keyId string, hash []byte) (signatureValue *[]byte, err error) {
		signature := sigMock
		return &signature, nil
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

	mock.ExpectQuery("SELECT passwordDigest FROM keyBindings").WithArgs(mockKeyId).
		WillReturnRows(sqlmock.NewRows([]string{"passwordDigest"}).AddRow(string(hashedPassword)))

	if err := keyUsageService.Sign(sessionId, password); err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery("SELECT keyId FROM keyBindings").WithArgs(user.UserId).
		WillReturnRows(sqlmock.NewRows([]string{"keyId"}).AddRow(string(mockKeyId)))

	keyId, err := keyUsageService.GetKeyId(user.UserId)
	if err != nil {
		t.Fatal(err)
	}

	if *keyId != mockKeyId {
		t.Fatalf("Invalid keyId")
	}

	getSessionStateMock = func(sessionId string) (sessionState *sm.SessionState, err error) {
		state := sm.SessionState{
			State: sm.SigningState{
				CurrentStateName: sm.SignedName,
				UserId:           user.UserId,
				KeyId:            mockKeyId,
				Dtbsr:            tbsd,
				SignInfo:         signInfo,
				Terminated:       false,
				SignatureValue:   sigMock,
			},
		}

		return &state, nil
	}

	if _, err := keyUsageService.GetSignature(sessionId); err != nil {
		t.Fatalf(err.Error())
	}

}
