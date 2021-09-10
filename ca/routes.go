package ca

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

func (ucs *UserCaService) SetupRoutes() {
	http.HandleFunc("/ca/create-certificate", ucs.createCertificateHandler)
	http.HandleFunc("/ca/get-certificate", ucs.getCertificateHandler)
}

type CreateSignatureResponse struct {
	SigningUrl string `json:"signingUrl"`
}

func (ucs *UserCaService) createCertificateHandler(w http.ResponseWriter, r *http.Request) {
	// takes a form with user info
	var body CreateCSRRequest

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	sessionId, err := ucs.CreateCSR(body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	url := fmt.Sprintf("%s/ssa/signatures/request?sessionId=%s", ucs.baseUrl, *sessionId)

	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(CreateSignatureResponse{SigningUrl: url})
}

type GetCertificateResponse struct {
	Certificates []KeyCert `json:"certificates"`
}

type KeyCert struct {
	KeyId       string `json:"keyId"`
	Certificate string `json:"certificate"`
}

func (ucs *UserCaService) getCertificateHandler(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("userid")
	if len(userId) == 0 {
		w.WriteHeader(http.StatusBadRequest)
	}

	var response GetCertificateResponse

	certRecords, err := ucs.GetCertificate(userId)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	for _, r := range *certRecords {
		response.Certificates = append(response.Certificates, KeyCert{
			KeyId:       r.KeyId,
			Certificate: base64.StdEncoding.EncodeToString(r.Cert.Raw),
		})
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
