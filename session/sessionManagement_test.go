package ssa

import (
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSessionManagementService(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectPrepare("INSERT INTO sessionEvents")
	mock.ExpectPrepare("SELECT name, event FROM sessionEvents")

	sessionService, err := CreateSessionService(db)
	if err != nil {
		t.Fatal(err)
	}

	userId := "userId"
	keyId := "keyId"
	tbsd := base64.StdEncoding.EncodeToString([]byte("some data"))

	mock.ExpectExec("INSERT INTO sessionEvents").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	sessionId, err := sessionService.CreateSession(userId)
	if err != nil {
		t.Fatal(err)
	}

	sha256WithRSAEncryptionOid := []int{1, 2, 840, 113549, 1, 1, 11}

	event := SignatureRequested{
		KeyId:          keyId,
		DataToBeSigned: tbsd,
		SignInfo: SignInfo{
			SignAlgo: pkix.AlgorithmIdentifier{Algorithm: sha256WithRSAEncryptionOid},
		}}

	mock.ExpectExec("INSERT INTO sessionEvents").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := sessionService.UpdateSession(*sessionId, &event); err != nil {
		t.Fatal(err)
	}

	rawEvent, _ := json.Marshal(event)

	signatureRequestedName := "signature_requested"

	mock.ExpectQuery("SELECT name, event FROM sessionEvents").
		WithArgs(sessionId).WillReturnRows(
		sqlmock.NewRows([]string{"name", "event"}).
			AddRow(signatureRequestedName, rawEvent))

	sessionState, err := sessionService.GetSessionState(*sessionId)
	if err != nil {
		t.Fatal(err)
	}

	if sessionState.State.CurrentStateName != signatureRequestedName {
		t.Fatal(errors.New("Invalid state"))
	}

	keyIdFromState, err := sessionState.State.GetKeyId()
	if err != nil {
		t.Fatal(err)
	}
	if *keyIdFromState != keyId {
		t.Fatal(errors.New("Unable to read event body"))
	}
}
