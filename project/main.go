package main

import (
	"github.com/jessevdk/go-flags"
	"log"
	"project/cmd"
)

func addCommands(parser *flags.Parser) error {
	_, err := parser.AddCommand(
		"dns01",
		"ACME DNS challenge",
		"Obtain (or revoke) HTTPS certificate using ACME DNS challenge",
		&cmd.DnsChallengeCommand{},
	)
	if err != nil {
		return err
	}
	_, err = parser.AddCommand(
		"http01",
		"ACME HTTP challenge",
		"Obtain (or revoke) HTTPS certificate using ACME HTTP challenge",
		&cmd.HttpChallengeCommand{},
	)
	if err != nil {
		return err
	}
	return nil
}
func main() {
	var opts struct{}
	parser := flags.NewParser(&opts, flags.Default)
	err := addCommands(parser)
	if err != nil {
		log.Fatal(err)
	}
	_, err = parser.Parse()
	if err != nil {
		log.Fatal(err)
	}
}
