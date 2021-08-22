package ssa

import "net/http"

func (s *SsaService) SetupRoutes() {
	http.HandleFunc("/create-user", s.userCreationHandler)
}

func (s *SsaService) userCreationHandler(w http.ResponseWriter, r *http.Request) {
	ks := *s.keyUsageService
	if _, err := ks.CreateAndBind("password"); err != nil {
		w.Write([]byte(err.Error()))
	}
}
