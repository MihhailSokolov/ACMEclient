package cmd

import (
	"log"
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
	return nil
}