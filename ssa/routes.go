package ssa

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	sm "github.com/hiddedorhout/ca_ssa/session"
)

func (s *SsaService) SetupRoutes() {
	http.HandleFunc("/create-user", s.userCreationHandler)
	http.HandleFunc("/signatures/create-request", s.createSignatureRequestHandler)
	http.HandleFunc("/signatures/request", s.signRequestHandler)
	http.HandleFunc("/signatures/sign", s.signHandler)
	http.HandleFunc("/signatures/get-signature", s.getsignatureHandler)
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

	ks := *s.keyUsageService

	keyId, err := ks.GetKeyId(req.UserId)
	if err != nil {
		w.Write([]byte(err.Error()))
	}

	if err := sms.UpdateSession(*sessionId, &sm.SignatureRequested{
		KeyId:          *keyId,
		DataToBeSigned: base64.StdEncoding.EncodeToString(tbsData),
		SignInfo: sm.SignInfo{
			SignAlgo: pkix.AlgorithmIdentifier{Algorithm: sha256WithRSAEncryptionOid},
		},
	}); err != nil {
		w.Write([]byte(err.Error()))
	}

	url := fmt.Sprintf("%s/signatures/request?sessionId=%s", s.baseUrl, *sessionId)

	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(CreateSignatureResponse{SigningUrl: url})
}

type signingResponse struct {
	Success bool `json:"success"`
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

	ks := *s.keyUsageService
	if err := ks.Sign(sessionId, password); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	} else {
		json.NewEncoder(w).Encode(signingResponse{Success: true})
	}

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
		Title:     "Sign",
		SessionId: sessionId,
	}

	if err := tmpl.Execute(w, data); err != nil {
		w.Write([]byte(err.Error()))
	}
}

type signatureResponse struct {
	SignatureValue string `json:"signatureValue"`
}

func (s *SsaService) getsignatureHandler(w http.ResponseWriter, r *http.Request) {
	sessionId := r.URL.Query().Get("sessionId")
	ks := *s.keyUsageService
	signatureValue, err := ks.GetSignature(sessionId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	} else {
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signatureResponse{
			SignatureValue: base64.StdEncoding.EncodeToString(*signatureValue),
		})
	}
}
