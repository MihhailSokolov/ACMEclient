package client

import (
	"log"
	"project/command"
)

func RunDnsChallenge(cmd command.DnsChallengeCommand) error {
	log.Println("Performing DNS challenge", cmd)
	return nil
}

func RunHttpChallenge(cmd command.HttpChallengeCommand) error {
	log.Println("Performing HTTP challenge", cmd)
	return nil
}