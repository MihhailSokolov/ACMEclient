package dns

import (
	"log"
	"net"
)
import "github.com/miekg/dns"

type dnsData struct {
	ip  string
	txt string
}

var dnsLookup = map[string]dnsData{}

func AddDnsRecord(domain string, ip string, txt string) {
	dnsLookup[domain] = dnsData{
		ip:  ip,
		txt: txt,
	}
}

type handler struct{}

func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeA:
		msg.Authoritative = true
		domain := msg.Question[0].Name
		data, ok := dnsLookup[domain]
		if ok {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(data.ip),
			})
		}
	case dns.TypeTXT:
		msg.Authoritative = true
		domain := msg.Question[0].Name
		data, ok := dnsLookup[domain]
		if ok {
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{data.txt},
			})
		}
		log.Println("DNS TXT request: Name=", domain, "; TXT=", data.txt)
	}
	err := w.WriteMsg(&msg)
	if err != nil {
		panic(err)
	}
}

func RunDnsServer() {
	server := &dns.Server{Addr: "0.0.0.0:10053", Net: "udp"}
	server.Handler = &handler{}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Error starting DNS server: %s\n", err.Error())
		}
		log.Println("Started a DNS server")
	}()
}
