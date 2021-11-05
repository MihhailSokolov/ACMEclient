package cmd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	acme "project/acme-client"
	dnsServer "project/dns"
	httpServer "project/http-server"
	"project/https"
	"time"
)

type DnsChallengeCommand struct {
	Dir     string   `long:"dir" required:"true"`
	Record  string   `long:"record" required:"true"`
	Domains []string `long:"domain" required:"true"`
	Revoke  bool     `long:"revoke"`
}

func (c *DnsChallengeCommand) Execute([]string) error {
	return RunDnsChallenge(*c)
}

type HttpChallengeCommand struct {
	Dir     string   `long:"dir" required:"true"`
	Record  string   `long:"record" required:"true"`
	Domains []string `long:"domain" required:"true"`
	Revoke  bool     `long:"revoke"`
}

func (c *HttpChallengeCommand) Execute([]string) error {
	return RunHttpChallenge(*c)
}

func RunDnsChallenge(cmd DnsChallengeCommand) error {
	log.Println("Starting DNS challenge")
	go dnsServer.RunDnsServer()
	log.Println("DNS server is running")
	httpClient, privateKey, err := initialization()
	log.Println("Initialization is done")
	resp, err := httpClient.Get(cmd.Dir)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)
	acmeDirectory := acme.AcmeDirectory{}
	err = json.NewDecoder(resp.Body).Decode(&acmeDirectory)
	if err != nil {
		return err
	}
	keyId, nonce, err := acme.CreateNewAcmeAccount(httpClient, privateKey, acmeDirectory)
	if err != nil {
		return err
	}
	log.Println("Created ACME account")
	authorizationUrls, dnsIdentifiers, finalizeUrl, nonce, err := acme.OrderCertificates(keyId, nonce, acmeDirectory, privateKey, httpClient, cmd.Domains)
	if err != nil {
		return err
	}
	log.Println("Ordered certificates")
	nonce, err = authorizeWithDns(keyId, nonce, privateKey, httpClient, authorizationUrls, dnsIdentifiers, cmd.Record)
	if err != nil {
		return err
	}
	log.Println("Authorized with DNS")
	certificateUrl, rsaPrivateKey, nonce, err := acme.SendCSR(keyId, nonce, finalizeUrl, dnsIdentifiers, privateKey, httpClient)
	if err != nil {
		return err
	}
	log.Println("Sent CSR")
	time.Sleep(time.Millisecond * 100)
	nonce, err = acme.DownloadCertificate(certificateUrl, keyId, nonce, httpClient, privateKey, rsaPrivateKey)
	if err != nil {
		return err
	}
	log.Println("Downloaded certificate")
	if cmd.Revoke {
		err = acme.RevokeCertificate(keyId, nonce, httpClient, acmeDirectory, privateKey)
		if err != nil {
			return err
		}
		log.Println("Revoked certificate")
	}
	time.Sleep(time.Millisecond * 100)
	go https.RunCertificateServer("server.cert", "server.key")
	log.Println("Started HTTPS server")
	return nil
}

func RunHttpChallenge(cmd HttpChallengeCommand) error {
	log.Println("Starting HTTP challenge")
	httpClient, privateKey, err := initialization()
	log.Println("Initialization is done")
	resp, err := httpClient.Get(cmd.Dir)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)
	acmeDirectory := acme.AcmeDirectory{}
	err = json.NewDecoder(resp.Body).Decode(&acmeDirectory)
	if err != nil {
		return err
	}
	keyId, nonce, err := acme.CreateNewAcmeAccount(httpClient, privateKey, acmeDirectory)
	if err != nil {
		return err
	}
	log.Println("Created an ACME account")
	authorizationUrls, dnsIdentifiers, finalizeUrl, nonce, err := acme.OrderCertificates(keyId, nonce, acmeDirectory, privateKey, httpClient, cmd.Domains)
	if err != nil {
		return err
	}
	log.Println("Ordered certificates")
	nonce, err = authorizeWithHttp(keyId, nonce, privateKey, httpClient, authorizationUrls)
	if err != nil {
		return err
	}
	log.Println("Authorized with HTTP")
	certificateUrl, rsaPrivateKey, nonce, err := acme.SendCSR(keyId, nonce, finalizeUrl, dnsIdentifiers, privateKey, httpClient)
	if err != nil {
		return err
	}
	log.Println("Sent CSR")
	time.Sleep(time.Millisecond * 100)
	nonce, err = acme.DownloadCertificate(certificateUrl, keyId, nonce, httpClient, privateKey, rsaPrivateKey)
	if err != nil {
		return err
	}
	log.Println("Downloaded certificate")
	if cmd.Revoke {
		err = acme.RevokeCertificate(keyId, nonce, httpClient, acmeDirectory, privateKey)
		if err != nil {
			return err
		}
		log.Println("Revoked certificate")
	}
	time.Sleep(time.Millisecond * 100)
	go https.RunCertificateServer("server.cert", "server.key")
	log.Println("Started HTTPS server")
	return nil
}

func initialization() (http.Client, ecdsa.PrivateKey, error) {
	pebbleCertificate, err := ioutil.ReadFile("pebble.minica.pem")
	if err != nil {
		panic(err)
	}
	certificatePool := x509.NewCertPool()
	certificatePool.AppendCertsFromPEM(pebbleCertificate)
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certificatePool,
			},
		},
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return client, *key, nil
}

func authorizeWithHttp(accountURL, nonce string, privateKey ecdsa.PrivateKey, httpClient http.Client, authorizationUrls []string) (string, error) {
	for _, authorizationUrl := range authorizationUrls {
		header := acme.CreateHeader(accountURL, nonce, authorizationUrl)
		signature := acme.SignMessage(header+".", privateKey)
		request, err := json.Marshal(acme.JWSMessage{
			Protected: header,
			Payload:   "",
			Signature: signature,
		})
		if err != nil {
			return "", err
		}
		response, err := httpClient.Post(authorizationUrl, "application/jose+json", bytes.NewBuffer(request))
		if err != nil {
			return "", err
		}
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return "", err
		}
		if response.StatusCode != 200 {
			return "", errors.New("authorization request error")
		}
		var authorizationResponse acme.AuthorizationResponse
		err = json.Unmarshal(body, &authorizationResponse)
		if err != nil {
			return "", err
		}
		challenge := acme.Challenge{}
		for _, c := range authorizationResponse.Challenges {
			if c.Type == "http-01" {
				challenge = c
				break
			}
		}
		nonce = response.Header.Get("Replay-Nonce")
		jwk, err := json.Marshal(acme.JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(privateKey.PublicKey.X.Bytes()),
			Y:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(privateKey.PublicKey.Y.Bytes()),
		})
		if err != nil {
			return "", err
		}
		sha256 := crypto.SHA256.New()
		sha256.Write(jwk)
		digest := sha256.Sum(nil)
		httpServer.RunChallengeServer(challenge.Token, challenge.Token+"."+base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(digest))
		time.Sleep(time.Millisecond * 100)
		header = acme.CreateHeader(accountURL, nonce, challenge.URL)
		payload := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte("{}"))
		signature = acme.SignMessage(header+"."+payload, privateKey)
		request, err = json.Marshal(acme.JWSMessage{
			Protected: header,
			Payload:   payload,
			Signature: signature,
		})
		if err != nil {
			return "", err
		}
		response, err = httpClient.Post(authorizationUrl, "application/jose+json", bytes.NewBuffer(request))
		if err != nil {
			return "", err
		}
		if response.StatusCode != 200 {
			return "", errors.New("authorization request error")
		}
		nonce = response.Header.Get("Replay-Nonce")
		header = acme.CreateHeader(accountURL, nonce, authorizationUrl)
		signature = acme.SignMessage(header+".", privateKey)
		request, err = json.Marshal(acme.JWSMessage{
			Protected: header,
			Payload:   "",
			Signature: signature,
		})
		if err != nil {
			return "", err
		}
		response, err = httpClient.Post(authorizationUrl, "application/jose+json", bytes.NewBuffer(request))
		if err != nil {
			return "", err
		}
		body, err = ioutil.ReadAll(response.Body)
		if err != nil {
			return "", err
		}
		if response.StatusCode != 200 {
			return "", errors.New("authorization check error")
		}
		var authorizationResult acme.AuthorizationResponse
		err = json.Unmarshal(body, &authorizationResult)
		if err != nil {
			return "", err
		}
		nonce = response.Header.Get("Replay-Nonce")
		if authorizationResult.Status != "valid" {
			return "", errors.New("authorization confirm error")
		}
	}
	return nonce, nil
}

func authorizeWithDns(keyId, nonce string, privateKey ecdsa.PrivateKey, httpClient http.Client, authorizationUrls []string, dnsIdentifiers []acme.Identifier, record string) (string, error) {
	for i, authorizationUrl := range authorizationUrls {
		header := acme.CreateHeader(keyId, nonce, authorizationUrl)
		signature := acme.SignMessage(header+".", privateKey)
		request, err := json.Marshal(acme.JWSMessage{
			Protected: header,
			Payload:   "",
			Signature: signature,
		})
		if err != nil {
			return "", err
		}
		response, err := httpClient.Post(authorizationUrl, "application/jose+json", bytes.NewBuffer(request))
		if err != nil {
			return "", err
		}
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return "", err
		}
		if response.StatusCode != 200 {
			return "", errors.New("authorization error")
		}
		var authorizationResponse acme.AuthorizationResponse
		err = json.Unmarshal(body, &authorizationResponse)
		if err != nil {
			return "", err
		}
		challenge := acme.Challenge{}
		for _, c := range authorizationResponse.Challenges {
			if c.Type == "dns-01" {
				challenge = c
				break
			}
		}
		nonce = response.Header.Get("Replay-Nonce")
		jwk, err := json.Marshal(acme.JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(privateKey.PublicKey.X.Bytes()),
			Y:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(privateKey.PublicKey.Y.Bytes()),
		})
		if err != nil {
			return "", err
		}
		sha256 := crypto.SHA256.New()
		sha256.Write(jwk)
		digest := sha256.Sum(nil)
		encodedDigest := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(digest)
		sha256 = crypto.SHA256.New()
		sha256.Write([]byte(challenge.Token + "." + encodedDigest))
		digest = sha256.Sum(nil)
		encodedDigest = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(digest)
		dnsServer.AddDnsRecord("_acme-challenge."+dnsIdentifiers[i].Value+".", record, encodedDigest)
		time.Sleep(time.Millisecond * 100)
		header = acme.CreateHeader(keyId, nonce, challenge.URL)
		payload := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte("{}"))
		signature = acme.SignMessage(header+"."+payload, privateKey)
		request, err = json.Marshal(acme.JWSMessage{
			Protected: header,
			Payload:   payload,
			Signature: signature,
		})
		if err != nil {
			return "", err
		}
		response, err = httpClient.Post(authorizationUrl, "application/jose+json", bytes.NewBuffer(request))
		if err != nil {
			return "", err
		}
		if response.StatusCode != 200 {
			return "", errors.New("authentication request error")
		}
		nonce = response.Header.Get("Replay-Nonce")
		header = acme.CreateHeader(keyId, nonce, authorizationUrl)
		signature = acme.SignMessage(header+".", privateKey)
		request, err = json.Marshal(acme.JWSMessage{
			Protected: header,
			Payload:   "",
			Signature: signature,
		})
		if err != nil {
			return "", err
		}
		response, err = httpClient.Post(authorizationUrl, "application/jose+json", bytes.NewBuffer(request))
		if err != nil {
			return "", err
		}
		body, err = ioutil.ReadAll(response.Body)
		if err != nil {
			return "", err
		}
		if response.StatusCode != 200 {
			return "", errors.New("authentication confirm error")
		}
		var authorizationResult acme.AuthorizationResponse
		err = json.Unmarshal(body, &authorizationResult)
		if err != nil {
			return "", err
		}
		nonce = response.Header.Get("Replay-Nonce")
		if authorizationResult.Status != "valid" {
			return "", errors.New("authorization check failed")
		}
	}
	return nonce, nil
}
