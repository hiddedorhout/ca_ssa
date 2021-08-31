package ssa

import (
	"database/sql"
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

type SessionService struct {
	db              *sql.DB
	storeEventStmnt *sql.Stmt
	getEventsStmnt  *sql.Stmt
}

type SessionState struct {
	events []Event
}

type Event interface {
	getName() string
}

var (
	signatureInitatedName  = "signature_initiated"
	signatureRequestedName = "signature_requested"
	signedName             = "signed"
	terminatedName         = "signing_session_terminated"
)

// Type of event
type SigningSessionInitiated struct {
	UserId string `json:"userId"`
}

func (si *SigningSessionInitiated) getName() string {
	return signatureInitatedName
}

// Type of event
type SignatureRequested struct {
	DataToBeSigned string `json:"dtbs"`
}

func (sr *SignatureRequested) getName() string {
	return signatureRequestedName
}

// Type of event
type Signed struct {
	SignatureValue string `json:"signatureValue"`
}

func (s *Signed) getName() string {
	return signedName
}

// Type of event
type Terminated struct {
	Reason string `json:"reason"`
}

func (s *Terminated) getName() string {
	return terminatedName
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

	if _, err := s.storeEventStmnt.Exec(eventId, sessionIdentifier, event.getName(), sessionInit); err != nil {
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

	if _, err := s.storeEventStmnt.Exec(eventId, sessionId, event.getName(), rawEvent); err != nil {
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

	if _, err := s.storeEventStmnt.Exec(eventId, sessionId, event.getName(), rawEvent); err != nil {
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
		case signatureInitatedName:
			var e Event
			var i SigningSessionInitiated
			if err := json.Unmarshal(payload, &i); err != nil {
				return nil, err
			}
			e = &i
			events = append(events, e)
		case signatureRequestedName:
			var e Event
			var i SignatureRequested
			if err := json.Unmarshal(payload, &i); err != nil {
				return nil, err
			}
			e = &i
			events = append(events, e)
		case signedName:
			var e Event
			var i Signed
			if err := json.Unmarshal(payload, &i); err != nil {
				return nil, err
			}
			e = &i
			events = append(events, e)
		case terminatedName:
			var e Event
			var i Terminated
			if err := json.Unmarshal(payload, &i); err != nil {
				return nil, err
			}
			e = &i
			events = append(events, e)
		default:
			return nil, errors.New("Unable to read events")
		}

	}
	return &SessionState{
		events: events,
	}, nil
}
