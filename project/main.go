package main

import (
	"github.com/jessevdk/go-flags"
	"log"
)

type DnsChallengeCommand struct {
	Dir     string   `long:"dir" required:"true"`
	Record  string   `long:"record" required:"true"`
	Domains []string `long:"domain" required:"true"`
	Revoke  bool     `long:"revoke"`
}

func (c *DnsChallengeCommand) Execute(args []string) error {
	log.Println("Performing DNS challenge", c)
	return nil
}

type HttpChallengeCommand struct {
	Dir     string   `long:"dir" required:"true"`
	Record  string   `long:"record" required:"true"`
	Domains []string `long:"domain" required:"true"`
	Revoke  bool     `long:"revoke"`
}

func (c *HttpChallengeCommand) Execute(args []string) error {
	log.Println("Performing HTTP challenge", c)
	return nil
}

func addCommands(parser *flags.Parser) error {
	_, err := parser.AddCommand(
		"dns01",
		"short help",
		"long help",
		&DnsChallengeCommand{},
	)
	if err != nil {
		return err
	}
	_, err = parser.AddCommand(
		"http01",
		"short help",
		"long help",
		&HttpChallengeCommand{},
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
