package ssa

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
)

func (s *SsaService) SetupRoutes() {
	http.HandleFunc("/create-user", s.userCreationHandler)
	http.HandleFunc("/signatures/create", s.createSignatureRequestHandler)
	http.HandleFunc("/signatures/request", s.signRequestHandler)
	http.HandleFunc("/signatures/sign", s.signHandler)
}

type createUserRequest struct {
	Password string `json:"password"`
}

func (s *SsaService) userCreationHandler(w http.ResponseWriter, r *http.Request) {

	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	ks := *s.keyUsageService
	user, err := ks.CreateAndBind(req.Password)
	if err != nil {
		w.Write([]byte(err.Error()))
	}

	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

type CreateSignatureRequest struct {
	UserId  string `json:"userId"`
	TbsData string `json:"dtbs"`
}

type CreateSignatureResponse struct {
	SigningUrl string `json:"signingUrl"`
}

func (s *SsaService) createSignatureRequestHandler(w http.ResponseWriter, r *http.Request) {
	// from body
	var req CreateSignatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid request body"))
	}
	rawBody, err := base64.StdEncoding.DecodeString(req.TbsData)
	if err != nil {
		w.Write([]byte(err.Error()))
	}

	h := sha256.New()
	h.Write(rawBody)
	tbsData := h.Sum(nil)

	sms := *s.sessionManagementService
	sessionId, err := sms.CreateSession(req.UserId)
	if err != nil {
		w.Write([]byte(err.Error()))
	}

	if err := sms.UpdateSession(*sessionId, &SignatureRequested{
		DataToBeSigned: base64.StdEncoding.EncodeToString(tbsData),
	}); err != nil {
		w.Write([]byte(err.Error()))
	}

	redirect := fmt.Sprintf("%s:%s/signatures/request?sessionId=%s", s.baseUrl, s.servicePort, *sessionId)

	w.Header().Add("Location", redirect)
	w.WriteHeader(http.StatusFound)
}

type signatureRequest struct {
	SessionId string
	Password  string
}

type signatureResponse struct {
	Signature string `json:"signature"`
}

func (s *SsaService) signHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	sessionId := r.Form.Get("sessionId")
	password := r.Form.Get("password")
	if len(sessionId) == 0 || len(password) == 0 {
		w.WriteHeader(http.StatusBadRequest)
	}

	sms := *s.sessionManagementService
	ks := *s.keyUsageService
	sessionState, err := sms.GetSessionState(sessionId)
	if err != nil {
		w.Write([]byte(err.Error()))
	}
	var keyId string
	signInfo := SignInfo{
		SignAlgo: pkix.AlgorithmIdentifier{Algorithm: sha256WithRSAEncryptionOid},
	}
	var signatureValue string

	var events []string
	for _, e := range sessionState.events {
		events = append(events, e.getName())
	}

	for _, e := range sessionState.events {
		switch e.getName() {
		case terminatedName:
			w.Write([]byte("Terminated/expired signing request"))
		case signatureInitatedName:
			init := e.(*SigningSessionInitiated)
			key, err := ks.GetKeyId(init.UserId)
			if err != nil {
				w.Write([]byte(err.Error()))
			}
			keyId = *key
		case signatureRequestedName:
			srn := e.(*SignatureRequested)
			if !contains(events, signedName) {
				tbsData, err := base64.StdEncoding.DecodeString(srn.DataToBeSigned)
				if err != nil {
					w.Write([]byte(err.Error()))
				}
				// Sign
				sv, err := ks.Sign(keyId, password, tbsData, signInfo)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(err.Error()))
				} else {
					signatureValue = base64.StdEncoding.EncodeToString(*sv)
				}
			}
		case signedName:
			s := e.(*Signed)
			signatureValue = s.SignatureValue
		}
	}

	response, _ := json.Marshal(signatureResponse{
		Signature: signatureValue,
	})
	w.Header().Add("Content-Type", "application/json")
	w.Write(response)
}

func (s *SsaService) signRequestHandler(w http.ResponseWriter, r *http.Request) {
	sessionId := r.URL.Query().Get("sessionId")
	if len(sessionId) == 0 {
		w.WriteHeader(http.StatusBadRequest)
	}

	tmpl, err := template.ParseFiles("ssa/templates/signing_request.html")
	if err != nil {
		w.WriteHeader(500)
	}

	data := struct {
		Title     string
		SessionId string
	}{
		Title:     "My page",
		SessionId: sessionId,
	}

	if err := tmpl.Execute(w, data); err != nil {
		w.Write([]byte(err.Error()))
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
