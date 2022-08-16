package main

import (
	"strconv"
	"time"

	"github.com/miekg/dns"
)

type DigParams struct {
	Short        bool
	Dnssec       bool
	Query        bool
	Check        bool
	Six          bool
	Four         bool
	Anchor       string
	Tsig         string
	Port         int
	Laddr        string
	Aa           bool
	Ad           bool
	Cd           bool
	Rd           bool
	Fallback     bool
	Tcp          bool
	TimeoutDial  time.Duration
	TimeoutRead  time.Duration
	TimeoutWrite time.Duration
	Nsid         bool
	Client       string
	Opcode       string
	Rcode        string

	Qclass     string
	Qtype      string
	Qname      string
	Nameserver string
}

type DigResult struct {
	Result *dns.Msg
	Errs   []string
	Extras []string
}

func (p *DigParams) DefaultValues() {
	if p.Port == 0 {
		p.Port = 53
	}
	if p.TimeoutDial < 2*time.Second {
		p.TimeoutDial = 2 * time.Second
	}
	if p.TimeoutDial < 2*time.Second {
		p.TimeoutDial = 2 * time.Second
	}
	if p.TimeoutRead < 2*time.Second {
		p.TimeoutRead = 2 * time.Second
	}
	if p.TimeoutWrite < 2*time.Second {
		p.TimeoutWrite = 2 * time.Second
	}
	if p.Opcode == "" {
		p.Opcode = "query"
	}
	if p.Rcode == "" {
		p.Rcode = "success"
	}
}

func (p *DigParams) UpdateFromMapString(params map[string]string) {
	for key, val := range params {
		switch key {
		case "short":
			if val == "true" {
				p.Short = true
			}
		case "dnssec":
			if val == "true" {
				p.Dnssec = true
			}
		case "query":
			if val == "true" {
				p.Query = true
			}
		case "check":
			if val == "true" {
				p.Check = true
			}
		case "six":
			if val == "true" {
				p.Six = true
			}
		case "four":
			if val == "true" {
				p.Four = true
			}
		case "anchor":
			p.Anchor = val
		case "tsig":
			p.Tsig = val
		case "port ":
			port, err := strconv.Atoi(val)
			if err != nil {
				p.Port = 53
			} else {
				p.Port = port
			}
		case "laddr":
			p.Laddr = val
		case "aa":
			if val == "true" {
				p.Aa = true
			}
		case "ad":
			if val == "true" {
				p.Ad = true
			}
		case "cd":
			if val == "true" {
				p.Cd = true
			}
		case "rd":
			if val == "false" {
				p.Rd = false
			} else {
				p.Rd = true
			}
		case "fallback":
			if val == "true" {
				p.Fallback = true
			}
		case "tcp":
			if val == "true" {
				p.Tcp = true
			}
		case "timeoutdial":
			dur, err := time.ParseDuration(val)
			if err != nil {
				p.TimeoutWrite = 2 * time.Second
			} else {
				p.TimeoutWrite = dur
			}
		case "timeoutread":
			dur, err := time.ParseDuration(val)
			if err != nil {
				p.TimeoutRead = 2 * time.Second
			} else {
				p.TimeoutRead = dur
			}
		case "timeoutwrite":
			dur, err := time.ParseDuration(val)
			if err != nil {
				p.TimeoutWrite = 2 * time.Second
			} else {
				p.TimeoutWrite = dur
			}
		case "nsid":
			if val == "true" {
				p.Nsid = true
			}
		case "client":
			p.Client = val
		case "opcode":
			p.Opcode = val
		case "rcode":
			p.Rcode = val
		case "qclass":
			p.Qclass = val
		case "qtype":
			p.Qtype = val
		case "qname":
			p.Qname = val
		case "nameserver":
			p.Nameserver = "@" + val

		}
	}
	// set default values if out of bounds or not present at creation
	if p.Port == 0 {
		p.Port = 53
	}
	if p.TimeoutDial < 2*time.Second {
		p.TimeoutDial = 2 * time.Second
	}
	if p.TimeoutDial < 2*time.Second {
		p.TimeoutDial = 2 * time.Second
	}
	if p.TimeoutRead < 2*time.Second {
		p.TimeoutRead = 2 * time.Second
	}
	if p.TimeoutWrite < 2*time.Second {
		p.TimeoutWrite = 2 * time.Second
	}
	if p.Opcode == "" {
		p.Opcode = "query"
	}
	if p.Rcode == "" {
		p.Rcode = "success"
	}
}
