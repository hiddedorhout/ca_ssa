package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	sm "github.com/hiddedorhout/ca_ssa/session"
	ssa "github.com/hiddedorhout/ca_ssa/ssa"
)

func TestUserCaService(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS userCertificates").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS root").WillReturnResult(sqlmock.NewResult(0, 0))

	mock.ExpectExec("INSERT INTO root").WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectPrepare("SELECT privateKey, certificate FROM root")
	mock.ExpectPrepare("INSERT INTO userCertificates")
	mock.ExpectPrepare("SELECT certificate FROM userCertificates")
	mock.ExpectPrepare("SELECT certificate FROM userCertificates")
	mock.ExpectPrepare("UPDATE userCertificates SET")

	// TEST DATA

	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	testPublicKey := testKey.Public().(*rsa.PublicKey)

	rawTestKey := x509.MarshalPKCS1PrivateKey(testKey)
	serial := createSerialNumber()

	template := x509.Certificate{
		Version: 2,
		Subject: pkix.Name{
			Country:    []string{"NL"},
			CommonName: "hiddedorhout.nl",
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}

	rawCert, err := x509.CreateCertificate(rand.Reader, &template, &template, testPublicKey, testKey)
	if err != nil {
		t.Fatal(err)
	}

	var smsMock sm.SessionManagement
	var ssaMock ssa.SsaService

	c := make(chan string)

	ucs, err := CreateUserCaService(db, smsMock, ssaMock, "baseUrl", "80", c)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery("SELECT privateKey, certificate FROM root").WithArgs(sqlmock.AnyArg()).WillReturnRows(
		sqlmock.NewRows([]string{"name", "event"}).
			AddRow(rawTestKey, rawCert))

	cert, key, err := ucs.getRootCertAndKeys()
	if err != nil {
		t.Fatal(err)
	}

	testCert, _ := x509.ParseCertificate(rawCert)

	if !cert.Equal(testCert) {
		t.Fatal("Invalid cert returned")
	}

	if !key.Equal(testKey) {
		t.Fatal("Invalid key returned")
	}

}
