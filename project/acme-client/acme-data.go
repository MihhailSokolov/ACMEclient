package acme_client

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type JWSMessage struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type Header struct {
	Alg   string `json:"alg"`
	Kid   string `json:"kid"`
	Nonce string `json:"nonce"`
	Url   string `json:"url"`
}

type NewAccountHeader struct {
	Alg   string `json:"alg"`
	Jwk   JWK    `json:"jwk"`
	Nonce string `json:"nonce"`
	Url   string `json:"url"`
}

type NewAccountPayload struct {
	TermsOfServiceAgreed bool `json:"termsOfServiceAgreed"`
}

type AcmeDirectory struct {
	NewNonce   string
	NewAccount string
	NewOrder   string
	RevokeCert string
	KeyChange  string
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type CertificateOrderResponse struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires"`
	Identifiers    []Identifier `json:"identifiers"`
	Finalize       string       `json:"finalize"`
	Authorizations []string     `json:"authorizations"`
}

type CertificateOrder struct {
	Status      string       `json:"status"`
	Identifiers []Identifier `json:"identifiers"`
	Expires     string       `json:"expires"`
}

type Challenge struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	Token string `json:"token"`
}

type AuthorizationResponse struct {
	Status      string       `json:"status"`
	Expires     string       `json:"expires"`
	Identifiers []Identifier `json:"identifiers"`
	Challenges  []Challenge  `json:"challenges"`
}

type CertificateSigningRequest struct {
	Csr string `json:"csr"`
}

type CertificateSigningRequestResponse struct {
	Status      string `json:"status"`
	Certificate string `json:"certificate"`
}

type RevocationOrder struct {
	Certificate string `json:"certificate"`
	Reason      int    `json:"reason"`
}
