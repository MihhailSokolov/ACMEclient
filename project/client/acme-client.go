package client

import (
	"io/ioutil"
	"log"
	"net/http"
	"project/http-server"
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
	log.Println("Performing DNS challenge", cmd)
	return nil
}

func RunHttpChallenge(cmd HttpChallengeCommand) error {
	log.Println("Performing HTTP challenge", cmd)
	http_server.RunChallengeServer("hello", "test")
	log.Println("Started HTTP server, sending request")
	resp, err := http.Get("http://localhost:5002/.well-known/acme-challenge/hello")
	if err != nil {
		log.Fatalln(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Response:")
	log.Println(string(body))
	return nil
}