package ca

import (
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

func (ucs *UserCaService) getCertificateHandler(w http.ResponseWriter, r *http.Request) {
	// input: userId
	// return certificate
}
