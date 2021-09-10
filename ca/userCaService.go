package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	sm "github.com/hiddedorhout/ca_ssa/session"
	ssa "github.com/hiddedorhout/ca_ssa/ssa"
)

var (
	rsaEncryptionOid           = []int{1, 2, 840, 113549, 1, 1, 1}
	sha256HashAlgoOid          = []int{2, 16, 840, 1, 101, 3, 4, 2, 1}
	sha256WithRSAEncryptionOid = []int{1, 2, 840, 113549, 1, 1, 11}
)

type UserCaService struct {
	db                         *sql.DB
	sessionService             *sm.SessionManagement
	keyUsage                   *ssa.KeyUsage
	getRootCertAndKeyStmnt     *sql.Stmt
	storeCertificateStmnt      *sql.Stmt
	getCertificateByUserStmnt  *sql.Stmt
	getCertificateByKeyIdStmnt *sql.Stmt
	blockCertificateStmnt      *sql.Stmt
	baseUrl                    string
	certCreationChannel        chan string
	caCertId                   string
}

func CreateUserCaService(db *sql.DB, sessionService sm.SessionManagement, sssa ssa.SsaService, baseUrl, port string, certCreationChannel chan string) (caService *UserCaService, err error) {

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS userCertificates (
		certificateSerial TEXT PRIMARY KEY,
		userId TEXT NOT NULL,
		keyId TEXT NOT NULL,
		certificate BLOB NOT NULL,
		active BOOLEAN NOT NULL CHECK (active IN (0, 1)),
		UNIQUE(certificateSerial) ON CONFLICT FAIL
	)`); err != nil {
		return nil, err
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS root (
		certificateSerial TEXT PRIMARY KEY,
		privateKey BLOB NOT NULL,
		certificate BLOB NOT NULL,
		UNIQUE(certificateSerial) ON CONFLICT FAIL
	)`); err != nil {
		return nil, err
	}

	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	publicKey := pkey.Public().(*rsa.PublicKey)

	rawPkey := x509.MarshalPKCS1PrivateKey(pkey)
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

	rawCert, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, pkey)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec("INSERT INTO root (certificateSerial, privateKey, certificate) values (?,?,?)", serial.String(), rawPkey, rawCert); err != nil {
		return nil, err
	}

	getRootCertAndKeyStmnt, err := db.Prepare("SELECT privateKey, certificate FROM root WHERE certificateSerial=?")
	if err != nil {
		return nil, err
	}

	storeCertificateStmnt, err := db.Prepare(`INSERT INTO userCertificates
	(certificateSerial, userId, keyId, certificate, active) values (?,?,?,?,?)`)
	if err != nil {
		return nil, err
	}

	getCertificateByUserStmnt, err := db.Prepare(`SELECT 
	certificate FROM userCertificates WHERE userId=? AND active=1`)
	if err != nil {
		return nil, err
	}

	getCertificateByKeyIdStmnt, err := db.Prepare(`SELECT 
	certificate FROM userCertificates WHERE keyId=? AND active=1`)
	if err != nil {
		return nil, err
	}

	blockCertificateStmnt, err := db.Prepare(`UPDATE 
	userCertificates SET active=0 WHERE userId=?`)
	if err != nil {
		return nil, err
	}

	var optionalPort string
	if port == "" {
		optionalPort = ""
	} else {
		optionalPort = fmt.Sprintf(":%s", port)
	}
	return &UserCaService{
		db:                         db,
		sessionService:             &sessionService,
		getRootCertAndKeyStmnt:     getRootCertAndKeyStmnt,
		keyUsage:                   sssa.KeyUsageService,
		storeCertificateStmnt:      storeCertificateStmnt,
		getCertificateByUserStmnt:  getCertificateByUserStmnt,
		getCertificateByKeyIdStmnt: getCertificateByKeyIdStmnt,
		blockCertificateStmnt:      blockCertificateStmnt,
		baseUrl:                    fmt.Sprintf("%s%s", baseUrl, optionalPort),
		certCreationChannel:        certCreationChannel,
		caCertId:                   serial.String(),
	}, nil
}

func (ucs *UserCaService) RunCertificateSigner() {
	go func() {
		for {
			sessionId := <-ucs.certCreationChannel
			if err := ucs.CreateCertificate(sessionId); err != nil {
				fmt.Println(err)
			}
		}
	}()
}

func (ucs *UserCaService) getRootCertAndKeys() (certificate *x509.Certificate, pKey *rsa.PrivateKey, err error) {
	var rawCert []byte
	var rawKey []byte
	if err := ucs.getRootCertAndKeyStmnt.QueryRow(ucs.caCertId).Scan(&rawKey, &rawCert); err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, nil, err
	}

	pkey, err := x509.ParsePKCS1PrivateKey(rawKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, pkey, nil
}

func (ucs *UserCaService) CreateCSR(csrRequest CreateCSRRequest) (sessionId *string, err error) {

	ku := *ucs.keyUsage
	ss := *ucs.sessionService
	keyId, err := ku.GetKeyId(csrRequest.UserId)
	if err != nil {
		return nil, err
	}

	sessionid, err := ss.CreateSession(csrRequest.UserId)
	if err != nil {
		return nil, err
	}

	certifcateSerial := uuid.NewString()
	unsignedCsr := x509.CertificateRequest{
		Version: 2,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("%v %v", csrRequest.FirstName, csrRequest.LastName),
			SerialNumber: certifcateSerial,
		},
	}

	if err := ss.UpdateSession(*sessionid, &sm.CSRSigningRequested{
		KeyId:       *keyId,
		UnsignedCsr: &unsignedCsr,
		SignInfo:    sm.SignInfo{SignAlgo: pkix.AlgorithmIdentifier{Algorithm: sha256WithRSAEncryptionOid}},
	}); err != nil {
		return nil, err
	}

	return sessionid, nil
}

func (ucs *UserCaService) CreateCertificate(sessionId string) error {
	// get event
	ss := *ucs.sessionService

	sessionState, err := ss.GetSessionState(sessionId)
	if err != nil {
		return err
	}

	signedCsr, err := sessionState.State.GetSignedCsr()
	if err != nil {
		return err
	}

	rootCertificate, pkey, err := ucs.getRootCertAndKeys()
	if err != nil {
		return err
	}

	template := x509.Certificate{
		RawSubject:              signedCsr.RawSubject,
		Version:                 signedCsr.Version,
		RawSubjectPublicKeyInfo: signedCsr.RawSubjectPublicKeyInfo,
		SerialNumber:            createSerialNumber(),
		NotBefore:               time.Now(),
		NotAfter:                time.Now().AddDate(1, 0, 0),
	}

	rawCert, err := x509.CreateCertificate(rand.Reader, &template, rootCertificate, pkey.Public().(*rsa.PublicKey), pkey)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return err
	}

	keyId, err := sessionState.State.GetKeyId()
	if err != nil {
		return err
	}

	serialString := cert.SerialNumber.String()

	if _, err := ucs.storeCertificateStmnt.Exec(serialString, sessionState.State.UserId, *keyId, rawCert, 1); err != nil {
		return err
	}
	return nil
}

func createSerialNumber() *big.Int {
	random, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serial := big.NewInt(random.Int64())
	return serial
}
