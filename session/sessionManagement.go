package ssa

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
)

type SessionManagement interface {
	CreateSession(userId string) (sessionId *string, err error)
	UpdateSession(sessionId string, event Event) error
	TerminateSession(sessionId, reason string) error
	GetSessionState(sessionId string) (sessionState *SessionState, err error)
}

type SignInfo struct {
	HashAlgo pkix.AlgorithmIdentifier `json:"hashAlgo"`
	SignAlgo pkix.AlgorithmIdentifier `json:"signAlgo"`
}

type SessionService struct {
	db              *sql.DB
	storeEventStmnt *sql.Stmt
	getEventsStmnt  *sql.Stmt
}

type SessionState struct {
	State SigningState
}

type State interface {
	GetStateName() string
	IsTerminated() bool
}

type Event interface {
	GetName() string
}

var (
	SignatureInitatedName   = "signature_initiated"
	SignatureRequestedName  = "signature_requested"
	SignedName              = "signed"
	TerminatedName          = "signing_session_terminated"
	CSRSigningRequestedName = "csr_signing_requested"
	CSRSignedName           = "csr_signed"
)

// Type of event
type SigningSessionInitiated struct {
	UserId string `json:"userId"`
}

func (si *SigningSessionInitiated) GetName() string {
	return SignatureInitatedName
}

// Type of event
type SignatureRequested struct {
	KeyId          string   `json:"keyId"`
	DataToBeSigned string   `json:"dtbs"`
	SignInfo       SignInfo `json:"signInfo"`
}

func (sr *SignatureRequested) GetName() string {
	return SignatureRequestedName
}

// Type of event
type Signed struct {
	SignatureValue string `json:"signatureValue"`
}

func (s *Signed) GetName() string {
	return SignedName
}

// Type of event
type Terminated struct {
	Reason string `json:"reason"`
}

func (s *Terminated) GetName() string {
	return TerminatedName
}

// Type of event
type CSRSigningRequested struct {
	KeyId       string                   `json:"keyId"`
	UnsignedCsr *x509.CertificateRequest `json:"unsignedCsr"`
	SignInfo    SignInfo                 `json:"signInfo"`
}

func (s *CSRSigningRequested) GetName() string {
	return CSRSigningRequestedName
}

// Type of event
type CSRSigned struct {
	Csr string `json:"signedCsr"`
}

func (s *CSRSigned) GetName() string {
	return CSRSignedName
}

type SigningState struct {
	CurrentStateName string
	UserId           string
	KeyId            string
	Dtbsr            []byte
	SignInfo         SignInfo
	SignatureValue   []byte
	SignedCsr        x509.CertificateRequest
	Terminated       bool
	TbsCsr           x509.CertificateRequest
}

func (s *SigningState) GetStateName() string {
	return s.CurrentStateName
}

func (s *SigningState) IsTerminated() bool {
	return s.Terminated
}

func (s *SigningState) GetKeyId() (*string, error) {
	if len(s.KeyId) == 0 {
		return nil, errors.New("keyId not set")
	} else {
		return &s.KeyId, nil
	}
}

func (s *SigningState) GetDtbsr() (*[]byte, error) {
	if len(s.Dtbsr) == 0 {
		return nil, errors.New("dtbsr not set")
	} else {
		return &s.Dtbsr, nil
	}
}

func (s *SigningState) GetSignInfo() (*SignInfo, error) {
	if len(s.SignInfo.SignAlgo.Algorithm.String()) == 0 {
		return nil, errors.New("SignInfo not set")
	} else {
		return &s.SignInfo, nil
	}
}

func (s *SigningState) GetTbsCsr() (*x509.CertificateRequest, error) {
	if len(s.TbsCsr.Subject.CommonName) == 0 {
		return nil, errors.New("tbs CSR value not set")
	} else {
		return &s.TbsCsr, nil
	}
}

func (s *SigningState) GetSignatureValue() (*[]byte, error) {
	if len(s.SignatureValue) == 0 {
		return nil, errors.New("Signature value not set")
	} else {
		return &s.SignatureValue, nil
	}
}

func (s *SigningState) GetSignedCsr() (*x509.CertificateRequest, error) {
	if len(s.SignedCsr.Signature) == 0 {
		return nil, errors.New("Signed CSR value not set")
	} else {
		return &s.SignedCsr, nil
	}
}

func CreateSessionService(db *sql.DB) (sessionService *SessionService, err error) {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS sessionEvents (
		eventId TEXT PRIMARY KEY,
		sessionId TEXT NOT NULL,
		name TEXT NOT NULL,
		event BLOB NOT NULL,
		UNIQUE(eventId) ON CONFLICT FAIL
	)`); err != nil {
		return nil, err
	}

	storeEventStmnt, err := db.Prepare(`INSERT INTO sessionEvents
	(eventId, sessionId, name, event) values (?,?,?,?)`)
	if err != nil {
		return nil, err
	}

	getEventsStmnt, err := db.Prepare(`SELECT 
	name, event FROM sessionEvents WHERE sessionId=?`)
	if err != nil {
		return nil, err
	}

	return &SessionService{
		db:              db,
		storeEventStmnt: storeEventStmnt,
		getEventsStmnt:  getEventsStmnt,
	}, nil
}

func (s *SessionService) CreateSession(userId string) (sessionId *string, err error) {
	sessionIdentifier := uuid.NewString()
	eventId := uuid.NewString()

	event := SigningSessionInitiated{
		UserId: userId,
	}

	sessionInit, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}

	if _, err := s.storeEventStmnt.Exec(eventId, sessionIdentifier, event.GetName(), sessionInit); err != nil {
		return nil, err
	}

	return &sessionIdentifier, nil
}

func (s *SessionService) UpdateSession(sessionId string, event Event) error {
	eventId := uuid.NewString()

	rawEvent, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if _, err := s.storeEventStmnt.Exec(eventId, sessionId, event.GetName(), rawEvent); err != nil {
		return err
	}
	return nil
}

func (s *SessionService) TerminateSession(sessionId, reason string) error {
	eventId := uuid.NewString()

	event := Terminated{
		Reason: reason,
	}

	rawEvent, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if _, err := s.storeEventStmnt.Exec(eventId, sessionId, event.GetName(), rawEvent); err != nil {
		return err
	}
	return nil
}

func (s *SessionService) GetSessionState(sessionId string) (sessionState *SessionState, err error) {
	rows, err := s.getEventsStmnt.Query(sessionId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event

	for rows.Next() {
		var name string
		var payload []byte
		if err := rows.Scan(&name, &payload); err != nil {
			return nil, err
		}

		switch name {
		case SignatureInitatedName:
			var e Event
			var i SigningSessionInitiated
			if err := json.Unmarshal(payload, &i); err != nil {
				return nil, err
			}
			e = &i
			events = append(events, e)
		case SignatureRequestedName:
			var e Event
			var i SignatureRequested
			if err := json.Unmarshal(payload, &i); err != nil {
				return nil, err
			}
			e = &i
			events = append(events, e)
		case SignedName:
			var e Event
			var i Signed
			if err := json.Unmarshal(payload, &i); err != nil {
				return nil, err
			}
			e = &i
			events = append(events, e)
		case TerminatedName:
			var e Event
			var i Terminated
			if err := json.Unmarshal(payload, &i); err != nil {
				return nil, err
			}
			e = &i
			events = append(events, e)
		case CSRSigningRequestedName:
			var e Event
			var i CSRSigningRequested
			if err := json.Unmarshal(payload, &i); err != nil {
				return nil, err
			}
			e = &i
			events = append(events, e)
		case CSRSignedName:
			var e Event
			var i CSRSigned
			if err := json.Unmarshal(payload, &i); err != nil {
				return nil, err
			}
			e = &i
			events = append(events, e)
		default:
			return nil, errors.New("Unable to read events")
		}

	}
	state, err := eventsToState(events)
	if err != nil {
		return nil, err
	}

	return &SessionState{
		State: *state,
	}, nil
}

func eventsToState(events []Event) (*SigningState, error) {
	var userId string
	var keyId string
	var dtbsr []byte
	var signInfo SignInfo
	var signatureValue []byte
	var isTerminated bool = false
	var tbsCsr x509.CertificateRequest
	var signedCsr x509.CertificateRequest

	var eventsNames []string
	for _, e := range events {
		switch e.GetName() {
		case TerminatedName:
			isTerminated = true
			eventsNames = append(eventsNames, e.GetName())
		case SignatureInitatedName:
			init := e.(*SigningSessionInitiated)
			userId = init.UserId
			eventsNames = append(eventsNames, e.GetName())
		case SignatureRequestedName:
			srn := e.(*SignatureRequested)
			tbsData, err := base64.StdEncoding.DecodeString(srn.DataToBeSigned)
			if err != nil {
				return nil, err
			}
			signInfo = srn.SignInfo
			dtbsr = tbsData
			keyId = srn.KeyId
			eventsNames = append(eventsNames, e.GetName())
		case CSRSigningRequestedName:
			csr := e.(*CSRSigningRequested)
			keyId = csr.KeyId
			signInfo = csr.SignInfo
			tbsCsr = *csr.UnsignedCsr
			eventsNames = append(eventsNames, e.GetName())
		case CSRSignedName:
			cs := e.(*CSRSigned)
			rawCsr, err := base64.StdEncoding.DecodeString(cs.Csr)
			if err != nil {
				return nil, err
			}
			csr, err := x509.ParseCertificateRequest(rawCsr)
			if err != nil {
				return nil, err
			}
			signedCsr = *csr
		case SignedName:
			s := e.(*Signed)
			sv, err := base64.StdEncoding.DecodeString(s.SignatureValue)
			if err != nil {
				return nil, err
			}
			signatureValue = sv
			eventsNames = append(eventsNames, e.GetName())
		}

	}

	return &SigningState{
		CurrentStateName: eventsNames[len(eventsNames)-1],
		UserId:           userId,
		KeyId:            keyId,
		Dtbsr:            dtbsr,
		TbsCsr:           tbsCsr,
		SignInfo:         signInfo,
		SignatureValue:   signatureValue,
		SignedCsr:        signedCsr,
		Terminated:       isTerminated,
	}, nil
}
