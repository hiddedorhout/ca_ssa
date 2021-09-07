package ca

import (
	"database/sql"

	sm "github.com/hiddedorhout/ca_ssa/session"
)

type UserCaService struct {
	db                         *sql.DB
	sessionService             sm.SessionManagement
	storeCertificateStmnt      *sql.Stmt
	getCertificateByUserStmnt  *sql.Stmt
	getCertificateByKeyIdStmnt *sql.Stmt
	blockCertificateStmnt      *sql.Stmt
}

func CreateUserCaService(db *sql.DB, sessionService sm.SessionManagement) (caService *UserCaService, err error) {

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS userCertificates (
		certificateId TEXT PRIMARY KEY,
		userId TEXT NOT NULL,
		keyId TEXT NOT NULL,
		certifcate BLOB NOT NULL,
		active BOOLEAN NOT NULL CHECK (active IN (0, 1)),
		UNIQUE(certificateId) ON CONFLICT FAIL
	)`); err != nil {
		return nil, err
	}

	storeCertificateStmnt, err := db.Prepare(`INSERT INTO userCertificates
	(certificateId, userId, keyId, certificate, active) values (?,?,?,?,?)`)
	if err != nil {
		return nil, err
	}

	getCertificateByUserStmnt, err := db.Prepare(`SELECT 
	userCertificates FROM certificates WHERE userId=? AND active=1`)
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

	return &UserCaService{
		db:                         db,
		sessionService:             sessionService,
		storeCertificateStmnt:      storeCertificateStmnt,
		getCertificateByUserStmnt:  getCertificateByUserStmnt,
		getCertificateByKeyIdStmnt: getCertificateByKeyIdStmnt,
		blockCertificateStmnt:      blockCertificateStmnt,
	}, nil
}

func (ucs *UserCaService) CreateCSR(csrRequest CreateCSRRequest) error

func (ucs *UserCaService) CreateCertificate(signedCsr []byte) error
