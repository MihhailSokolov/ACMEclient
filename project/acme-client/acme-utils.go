package acme_client

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

func SignMessage(message string, privateKey ecdsa.PrivateKey) string {
	const hashLen = 32
	sha256 := crypto.SHA256.New()
	sha256.Write([]byte(message))
	digest := sha256.Sum(nil)
	r, s, _ := ecdsa.Sign(rand.Reader, &privateKey, digest)
	paddedR := append(make([]byte, hashLen-len(r.Bytes())), r.Bytes()...)
	paddedS := append(make([]byte, hashLen-len(s.Bytes())), s.Bytes()...)
	signature := append(paddedR, paddedS...)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(signature)
}

func CreateHeader(keyId, nonce, url string) string {
	header, err := json.Marshal(Header{
		Alg:   "ES256",
		Kid:   keyId,
		Nonce: nonce,
		Url:   url,
	})
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(header)
}

func CreateNewAcmeAccount(client http.Client, key ecdsa.PrivateKey, acmeDir AcmeDirectory) (string, string, error) {
	response, err := client.Head(acmeDir.NewNonce)
	if err != nil {
		return "", "", err
	}
	nonce := response.Header.Get("Replay-Nonce")
	headerData, err := json.Marshal(NewAccountHeader{
		Alg: "ES256",
		Jwk: JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(key.PublicKey.X.Bytes()),
			Y:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(key.PublicKey.Y.Bytes()),
		},
		Nonce: nonce,
		Url:   acmeDir.NewAccount,
	})
	if err != nil {
		return "", "", err
	}
	header := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(headerData)
	payloadData, err := json.Marshal(NewAccountPayload{TermsOfServiceAgreed: true})
	if err != nil {
		return "", "", nil
	}
	payload := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(payloadData)
	signature := SignMessage(header+"."+payload, key)
	request, err := json.Marshal(JWSMessage{
		Protected: header,
		Payload:   payload,
		Signature: signature,
	})
	if err != nil {
		return "", "", err
	}
	response, err = client.Post(acmeDir.NewAccount, "application/jose+json", bytes.NewBuffer(request))
	if err != nil {
		return "", "", err
	}
	if response.StatusCode != 201 {
		return "", "", errors.New("account creation error")
	}
	return response.Header.Get("Location"), response.Header.Get("Replay-Nonce"), nil
}

func OrderCertificates(keyId, nonce string, acmeDir AcmeDirectory, key ecdsa.PrivateKey, client http.Client, domains []string) ([]string, []Identifier, string, string, error) {
	header := CreateHeader(keyId, nonce, acmeDir.NewOrder)
	var dnsIdentifiers []Identifier
	for _, identifier := range domains {
		dnsIdentifiers = append(dnsIdentifiers, Identifier{Type: "dns", Value: identifier})
	}
	payloadData, err := json.Marshal(CertificateOrder{
		Status:      "pending",
		Identifiers: dnsIdentifiers,
		Expires:     "2022-11-05T12:00:00Z",
	})
	if err != nil {
		return nil, nil, "", "", err
	}
	payload := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(payloadData)
	signature := SignMessage(header+"."+payload, key)
	request, err := json.Marshal(JWSMessage{
		Protected: header,
		Payload:   payload,
		Signature: signature,
	})
	if err != nil {
		return nil, nil, "", "", err
	}
	response, err := client.Post(acmeDir.NewOrder, "application/jose+json", bytes.NewBuffer(request))
	if err != nil {
		return nil, nil, "", "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(response.Body)
	log.Println(response) // TODO: Remove
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, nil, "", "", err
	}
	log.Println(string(body)) // TODO: Remove
	if response.StatusCode != 201 {
		return nil, nil, "", "", errors.New("order was not successful")
	}
	var orderResponse CertificateOrderResponse
	err = json.Unmarshal(body, &orderResponse)
	if err != nil {
		return nil, nil, "", "", err
	}
	return orderResponse.Authorizations, orderResponse.Identifiers, orderResponse.Finalize, response.Header.Get("Replay-Nonce"), nil
}

func SendCSR(keyId, nonce, finalizeUrl string, dnsIdentifiers []Identifier, key ecdsa.PrivateKey, client http.Client) (string, rsa.PrivateKey, string, error) {
	var dnsNames []string
	for _, dns := range dnsIdentifiers {
		dnsNames = append(dnsNames, dns.Value)
	}
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", rsa.PrivateKey{}, "", err
	}
	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			SignatureAlgorithm: x509.SHA256WithRSA,
			Subject: pkix.Name{
				CommonName:         dnsNames[0],
				Country:            []string{"CH"},
				Province:           []string{"Zurich Canton"},
				Locality:           []string{"Zurich"},
				Organization:       []string{"ETH Zurich"},
				OrganizationalUnit: []string{"D-INFK"},
			},
			DNSNames: dnsNames,
		},
		rsaPrivateKey,
	)
	if err != nil {
		return "", rsa.PrivateKey{}, "", err
	}
	csrMessage, err := json.Marshal(CertificateSigningRequest{
		Csr: base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(csr),
	})
	if err != nil {
		return "", rsa.PrivateKey{}, "", err
	}
	header := CreateHeader(keyId, nonce, finalizeUrl)
	payload := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(csrMessage)
	signature := SignMessage(header+"."+payload, key)
	request, err := json.Marshal(JWSMessage{
		Protected: header,
		Payload:   payload,
		Signature: signature,
	})
	if err != nil {
		return "", rsa.PrivateKey{}, "", err
	}
	response, err := client.Post(finalizeUrl, "application/jose+json", bytes.NewBuffer(request))
	if err != nil {
		return "", rsa.PrivateKey{}, "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(response.Body)
	if response.StatusCode != 200 {
		return "", rsa.PrivateKey{}, "", errors.New("csr error")
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", rsa.PrivateKey{}, "", err
	}
	csrResponse := CertificateSigningRequestResponse{}
	err = json.Unmarshal(body, &csrResponse)
	if err != nil {
		return "", rsa.PrivateKey{}, "", err
	}
	var certificateUrl string
	for {
		nonce = response.Header.Get("Replay-Nonce")
		if csrResponse.Status == "processing" {
			retryAfter := response.Header.Get("Retry-After")
			wait, err := strconv.ParseInt(retryAfter, 10, 0)
			if err != nil {
				wait = 100
			}
			time.Sleep(time.Duration(wait) * time.Millisecond)
		}
		if csrResponse.Status == "valid" {
			certificateUrl = csrResponse.Certificate
			break
		}
		resource := response.Header.Get("Location")
		header = CreateHeader(keyId, nonce, resource)
		signature := SignMessage(header+".", key)
		request, err := json.Marshal(JWSMessage{
			Protected: header,
			Payload:   "",
			Signature: signature,
		})
		if err != nil {
			return "", rsa.PrivateKey{}, "", err
		}

		response, err = client.Post(resource, "application/jose+json", bytes.NewBuffer(request))
		if err != nil {
			return "", rsa.PrivateKey{}, "", err
		}
		if response.StatusCode != 200 {
			return "", rsa.PrivateKey{}, "", errors.New("csr confirmation error")
		}
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return "", rsa.PrivateKey{}, "", err
		}
		err = json.Unmarshal(body, &csrResponse)
		if err != nil {
			return "", rsa.PrivateKey{}, "", err
		}
	}
	return certificateUrl, *rsaPrivateKey, response.Header.Get("Replay-Nonce"), nil
}

func DownloadCertificate(certificateUrl, keyId, nonce string, client http.Client, key ecdsa.PrivateKey, rsaKey rsa.PrivateKey) (string, error) {
	header := CreateHeader(keyId, nonce, certificateUrl)
	signature := SignMessage(header+".", key)
	request, err := json.Marshal(JWSMessage{
		Protected: header,
		Payload:   "",
		Signature: signature,
	})
	if err != nil {
		return "", err
	}
	response, err := client.Post(certificateUrl, "application/jose+json", bytes.NewBuffer(request))
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(response.Body)
	if response.StatusCode != 200 {
		return "", errors.New("certificate downloading error")
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	err = ioutil.WriteFile("server.cert", body, os.FileMode(0644))
	if err != nil {
		return "", err
	}
	err = ioutil.WriteFile("server.key", pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(&rsaKey),
		},
	), os.FileMode(0644))
	if err != nil {
		return "", err
	}
	nonce = response.Header.Get("Replay-Nonce")
	return nonce, nil
}

func RevokeCertificate(keyId, nonce string, client http.Client, acmeDir AcmeDirectory, key ecdsa.PrivateKey) error {
	header := CreateHeader(keyId, nonce, acmeDir.RevokeCert)
	certificate, err := ioutil.ReadFile("server.cert")
	if err != nil {
		return err
	}
	decodedCertificate, _ := pem.Decode(certificate)
	revocation, err := json.Marshal(RevocationOrder{
		Certificate: base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(decodedCertificate.Bytes),
	})
	if err != nil {
		return err
	}
	payload := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(revocation)
	signature := SignMessage(header+"."+payload, key)
	request, err := json.Marshal(JWSMessage{
		Protected: header,
		Payload:   payload,
		Signature: signature,
	})
	if err != nil {
		return err
	}
	response, err := client.Post(acmeDir.RevokeCert, "application/jose+json", bytes.NewBuffer(request))
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return errors.New("revocation error")
	}
	return nil
}
