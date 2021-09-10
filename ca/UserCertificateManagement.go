package ca

type CreateCSRRequest struct {
	UserId    string `json:"userId"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type UserCertificateManagement interface {
	CreateCSR(CreateCSRRequest) error
	CreateCertificate(signedCsr []byte) error
	GetCertificate(userId string) (*[]CertRecord, error)
}
