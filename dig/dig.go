// license that can be found in the LICENSE file.

// Q is a small utility which acts and behaves like 'dig' from BIND.
// It is meant to stay lean and mean, while having a bunch of handy
// features, like -check which checks if a packet is correctly signed (without
// checking the chain of trust).
// When using -check a comment is printed:
//
// ;+ Secure signature, miek.nl. RRSIG(SOA) validates (DNSKEY miek.nl./4155/net)
//
// which says the SOA has a valid RRSIG and it validated with the DNSKEY of miek.nl,
// which has key id 4155 and is retrieved from the server. Other values are 'disk'.
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	//"gopkg.in/yaml.v2"
	"github.com/miekg/dns"
	//"github.com/spf13/viper"
)

var dnskey *dns.DNSKEY

func Dig(p DigParams) (digres DigResult) {

	var (
		// function sets and uses these. leave for now.
		qtype  []uint16
		qclass []uint16
		qname  []string

		// function manipulates these. leave for now.
		dnssec     bool   = p.Dnssec
		fallback   bool   = p.Fallback
		nameserver string = p.Nameserver

		// I'm lazy, so put all the stuff to return in this thing here
		//digres digResult
	)

	if p.Anchor != "" {
		f, err := os.Open(p.Anchor)
		if err != nil {
			//fmt.Fprintf(os.Stderr, "Failure to open %s: %s\n", p.Anchor, err.Error())
			digres.Errs = append(digres.Errs, fmt.Sprintf("Failure to open %s: %s\n", p.Anchor, err.Error()))
		}
		r, err := dns.ReadRR(f, p.Anchor)
		if err != nil {
			//fmt.Fprintf(os.Stderr, "Failure to read an RR from %s: %s\n", p.Anchor, err.Error())
			digres.Errs = append(digres.Errs, fmt.Sprintf("Failure read an RR from %s: %s\n", p.Anchor, err.Error()))
		}
		if k, ok := r.(*dns.DNSKEY); !ok {
			//fmt.Fprintf(os.Stderr, "No DNSKEY read from %s\n", p.Anchor)
			digres.Errs = append(digres.Errs, fmt.Sprintf("No DNSKEY read from %s\n", p.Anchor))
		} else {
			dnskey = k
		}
	}

	if strings.HasPrefix(p.Qtype, "TYPE") {
		i, err := strconv.Atoi(p.Qtype[4:])
		if err == nil {
			qtype = append(qtype, uint16(i))
		}
	} else {
		if k, ok := dns.StringToType[strings.ToUpper(p.Qtype)]; ok {
			qtype = append(qtype, k)
		}

	}
	if strings.HasPrefix(p.Qclass, "CLASS") {
		i, err := strconv.Atoi(p.Qclass[5:])
		if err == nil {
			qclass = append(qclass, uint16(i))
		}
	} else {
		if k, ok := dns.StringToClass[strings.ToUpper(p.Qclass)]; ok {
			qclass = append(qclass, k)
		}
	}
	qname = append(qname, p.Qname)

	if len(qname) == 0 {
		qname = []string{"."}
		if len(qtype) == 0 {
			qtype = append(qtype, dns.TypeNS)
		}
	}
	if len(qtype) == 0 {
		qtype = append(qtype, dns.TypeA)
	}
	if len(qclass) == 0 {
		qclass = append(qclass, dns.ClassINET)
	}

	if len(nameserver) == 0 {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		nameserver = "@" + conf.Servers[0]
	}

	nameserver = string([]byte(nameserver)[1:]) // chop off @
	// if the nameserver is from /etc/resolv.conf the [ and ] are already
	// added, thereby breaking net.ParseIP. Check for this and don't
	// fully qualify such a name
	if nameserver[0] == '[' && nameserver[len(nameserver)-1] == ']' {
		nameserver = nameserver[1 : len(nameserver)-1]
	}
	if i := net.ParseIP(nameserver); i != nil {
		//nameserver = net.JoinHostPort(nameserver, strconv.Itoa(port))
		nameserver = net.JoinHostPort(nameserver, strconv.Itoa(p.Port))
	} else {
		//nameserver = dns.Fqdn(nameserver) + ":" + strconv.Itoa(port)
		nameserver = dns.Fqdn(nameserver) + ":" + strconv.Itoa(p.Port)
	}
	c := new(dns.Client)
	t := new(dns.Transfer)
	c.Net = "udp"
	if p.Four {
		c.Net = "udp4"
	}
	if p.Six {
		c.Net = "udp6"
	}
	if p.Tcp {
		c.Net = "tcp"
		if p.Four {
			c.Net = "tcp4"
		}
		if p.Six {
			c.Net = "tcp6"
		}
	}
	c.DialTimeout = p.TimeoutDial
	c.ReadTimeout = p.TimeoutRead
	c.WriteTimeout = p.TimeoutWrite

	if p.Laddr != "" {
		c.Dialer = &net.Dialer{Timeout: c.DialTimeout}
		ip := net.ParseIP(p.Laddr)
		if p.Tcp {
			c.Dialer.LocalAddr = &net.TCPAddr{IP: ip}
		} else {
			c.Dialer.LocalAddr = &net.UDPAddr{IP: ip}
		}
	}

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     p.Aa,
			AuthenticatedData: p.Ad,
			CheckingDisabled:  p.Cd,
			RecursionDesired:  p.Rd,
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}
	if op, ok := dns.StringToOpcode[strings.ToUpper(p.Opcode)]; ok {
		m.Opcode = op
	}
	m.Rcode = dns.RcodeSuccess
	if rc, ok := dns.StringToRcode[strings.ToUpper(p.Rcode)]; ok {
		m.Rcode = rc
	}

	if dnssec || p.Nsid || p.Client != "" {
		o := &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
			},
		}
		if dnssec {
			o.SetDo()
			o.SetUDPSize(dns.DefaultMsgSize)
		}
		if p.Nsid {
			e := &dns.EDNS0_NSID{
				Code: dns.EDNS0NSID,
			}
			o.Option = append(o.Option, e)
			// NSD will not return nsid when the udp message size is too small
			o.SetUDPSize(dns.DefaultMsgSize)
		}
		if p.Client != "" {
			e := &dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Address:       net.ParseIP(p.Client),
				Family:        1, // IP4
				SourceNetmask: net.IPv4len * 8,
			}

			if e.Address == nil {
				//fmt.Fprintf(os.Stderr, "Failure to parse IP address: %s\n", p.Client)
				digres.Errs = append(digres.Errs, fmt.Sprintf("Failure to parse IP address: %s\n", p.Client))
				//return
			}

			if e.Address.To4() == nil {
				e.Family = 2 // IP6
				e.SourceNetmask = net.IPv6len * 8
			}
			o.Option = append(o.Option, e)
		}
		m.Extra = append(m.Extra, o)
	}
	if p.Tcp {
		co := new(dns.Conn)
		tcp := "tcp"
		if p.Six {
			tcp = "tcp6"
		}
		var err error

		if c.Dialer != nil {
			co.Conn, err = c.Dialer.Dial(tcp, nameserver)
		} else {
			co.Conn, err = net.DialTimeout(tcp, nameserver, p.TimeoutDial)
		}

		if err != nil {
			//fmt.Fprintf(os.Stderr, "Dialing "+nameserver+" failed: "+err.Error()+"\n")
			digres.Errs = append(digres.Errs, fmt.Sprintf("Dialing "+nameserver+" failed: "+err.Error()+"\n"))
			//return
		}

		defer co.Close()
		qt := dns.TypeA
		qc := uint16(dns.ClassINET)
		for i, v := range qname {
			if i < len(qtype) {
				qt = qtype[i]
			}
			if i < len(qclass) {
				qc = qclass[i]
			}
			m.Question[0] = dns.Question{Name: dns.Fqdn(v), Qtype: qt, Qclass: qc}
			m.Id = dns.Id()
			if p.Tsig != "" {
				if algo, name, secret, ok := tsigKeyParse(p.Tsig); ok {
					m.SetTsig(name, algo, 300, time.Now().Unix())
					c.TsigSecret = map[string]string{name: secret}
					t.TsigSecret = map[string]string{name: secret}
				} else {
					//fmt.Fprintf(os.Stderr, ";; TSIG key data error\n")
					digres.Errs = append(digres.Errs, fmt.Sprintf(";; TSIG key data error\n"))
					continue
				}
			}
			co.SetReadDeadline(time.Now().Add(p.TimeoutRead))
			co.SetWriteDeadline(time.Now().Add(p.TimeoutWrite))

			if p.Query {
				//fmt.Printf("%s", m.String())
				//fmt.Printf("\n;; size: %d bytes\n\n", m.Len())
				digres.Extras = append(digres.Extras, fmt.Sprintf("%s\n;; size: %d bytes\n\n", m.String(), m.Len()))
			}
			then := time.Now()
			if err := co.WriteMsg(m); err != nil {
				//fmt.Fprintf(os.Stderr, ";; %s\n", err.Error())
				digres.Errs = append(digres.Errs, fmt.Sprintf(";; %s\n", err.Error()))
				continue
			}
			r, err := co.ReadMsg()
			if err != nil {
				//fmt.Fprintf(os.Stderr, ";; %s\n", err.Error())
				digres.Errs = append(digres.Errs, fmt.Sprintf(";; %s\n", err.Error()))
				continue
			}
			rtt := time.Since(then)
			if r.Id != m.Id {
				//fmt.Fprintf(os.Stderr, "Id mismatch\n")
				digres.Errs = append(digres.Errs, fmt.Sprintf("Id mismatch\n"))
				continue
			}

			if p.Check {
				sigCheck(r, nameserver, true)
				denialCheck(r)
				fmt.Println()
			}
			if p.Short {
				shortenMsg(r)
			}

			//fmt.Printf("%v", r)
			//fmt.Printf("\n;; query time: %.3d µs, server: %s(%s), size: %d bytes\n", rtt/1e3, nameserver, tcp, r.Len())
			digres.Result = r
			digres.Extras = append(digres.Extras, fmt.Sprintf("\n;; query time: %.3d µs, server: %s(%s), size: %d bytes\n", rtt/1e3, nameserver, tcp, r.Len()))
		}
		return
	}

	qt := dns.TypeA
	qc := uint16(dns.ClassINET)

Query:
	for i, v := range qname {
		if i < len(qtype) {
			qt = qtype[i]
		}
		if i < len(qclass) {
			qc = qclass[i]
		}
		m.Question[0] = dns.Question{Name: dns.Fqdn(v), Qtype: qt, Qclass: qc}
		m.Id = dns.Id()
		if p.Tsig != "" {
			if algo, name, secret, ok := tsigKeyParse(p.Tsig); ok {
				m.SetTsig(name, algo, 300, time.Now().Unix())
				c.TsigSecret = map[string]string{name: secret}
				t.TsigSecret = map[string]string{name: secret}
			} else {
				//fmt.Fprintf(os.Stderr, "TSIG key data error\n")
				digres.Errs = append(digres.Errs, fmt.Sprintf(";; TSIG key data error\n"))
				continue
			}
		}
		if p.Query {
			//fmt.Printf("%s", m.String())
			//fmt.Printf("\n;; size: %d bytes\n\n", m.Len())
			digres.Extras = append(digres.Extras, fmt.Sprintf("%s\n;; size: %d bytes\n\n", m.String(), m.Len()))
		}
		if qt == dns.TypeAXFR || qt == dns.TypeIXFR {
			env, err := t.In(m, nameserver)
			if err != nil {
				fmt.Printf(";; %s\n", err.Error())
				//digres.Errs = append(digres.Errs, fmt.Printf(";; %s\n", err.Error()))
				continue
			}
			var envelope, record int
			for e := range env {
				if e.Error != nil {
					fmt.Printf(";; %s\n", e.Error.Error())
					//digres.Errs = append(digres.Errs, fmt.Printf(";; %s\n", e.Error.Error()))
					continue Query
				}
				for _, r := range e.RR {
					fmt.Printf("%s\n", r)
				}
				record += len(e.RR)
				envelope++
			}
			fmt.Printf("\n;; xfr size: %d records (envelopes %d)\n", record, envelope)
			continue
		}
		r, rtt, err := c.Exchange(m, nameserver)
	Redo:
		switch err {
		case nil:
			//do nothing
		default:
			fmt.Printf(";; %s\n", err.Error())
			continue
		}
		if r.Truncated {
			if fallback {
				if !dnssec {
					fmt.Printf(";; Truncated, trying %d bytes bufsize\n", dns.DefaultMsgSize)
					o := new(dns.OPT)
					o.Hdr.Name = "."
					o.Hdr.Rrtype = dns.TypeOPT
					o.SetUDPSize(dns.DefaultMsgSize)
					m.Extra = append(m.Extra, o)
					r, rtt, err = c.Exchange(m, nameserver)
					dnssec = true
					goto Redo
				} else {
					// First EDNS, then TCP
					fmt.Printf(";; Truncated, trying TCP\n")
					c.Net = "tcp"
					r, rtt, err = c.Exchange(m, nameserver)
					fallback = false
					goto Redo
				}
			}
			fmt.Printf(";; Truncated\n")
		}
		if r.Id != m.Id {
			fmt.Fprintf(os.Stderr, "Id mismatch\n")
			//return
		}

		if p.Check {
			sigCheck(r, nameserver, p.Tcp)
			denialCheck(r)
			fmt.Println()
		}
		if p.Short {
			shortenMsg(r)
		}

		//fmt.Printf("YARR!\n %+v\n", r.Answer[0].Header().Ttl)
		//nsr := strings.Fields(r.Answer[0].String())
		//fmt.Printf("YARR!\n %+v\n", nsr[len(nsr)-1])
		//fmt.Printf("YARR!\n %+v\n", nsr[len(nsr)-1])
		//fmt.Printf("%T", r)
		//fmt.Printf("\n;; query time: %.3d µs, server: %s(%s), size: %d bytes\n", rtt/1e3, nameserver, c.Net, r.Len())

		//fmt.Printf("%v", r)
		digres.Result = r
		digres.Extras = append(digres.Extras, fmt.Sprintf("\n;; query time: %.3d µs, server: %s(%s), size: %d bytes\n", rtt/1e3, nameserver, c.Net, r.Len()))
	}
	return
}

func tsigKeyParse(s string) (algo, name, secret string, ok bool) {
	s1 := strings.SplitN(s, ":", 3)
	switch len(s1) {
	case 2:
		return "hmac-md5.sig-alg.reg.int.", dns.Fqdn(s1[0]), s1[1], true
	case 3:
		switch s1[0] {
		case "hmac-md5":
			return "hmac-md5.sig-alg.reg.int.", dns.Fqdn(s1[1]), s1[2], true
		case "hmac-sha1":
			return "hmac-sha1.", dns.Fqdn(s1[1]), s1[2], true
		case "hmac-sha256":
			return "hmac-sha256.", dns.Fqdn(s1[1]), s1[2], true
		}
	}
	return
}

func sectionCheck(set []dns.RR, server string, tcp bool) {
	var key *dns.DNSKEY
	for _, rr := range set {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			var expired string
			if !rr.(*dns.RRSIG).ValidityPeriod(time.Now().UTC()) {
				expired = "(*EXPIRED*)"
			}
			rrset := getRRset(set, rr.Header().Name, rr.(*dns.RRSIG).TypeCovered)
			if dnskey == nil {
				key = getKey(rr.(*dns.RRSIG).SignerName, rr.(*dns.RRSIG).KeyTag, server, tcp)
			} else {
				key = dnskey
			}
			if key == nil {
				fmt.Printf(";? DNSKEY %s/%d not found\n", rr.(*dns.RRSIG).SignerName, rr.(*dns.RRSIG).KeyTag)
				continue
			}
			where := "net"
			if dnskey != nil {
				where = "disk"
			}
			if err := rr.(*dns.RRSIG).Verify(key, rrset); err != nil {
				fmt.Printf(";- Bogus signature, %s does not validate (DNSKEY %s/%d/%s) [%s] %s\n",
					shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), where, err.Error(), expired)
			} else {
				fmt.Printf(";+ Secure signature, %s validates (DNSKEY %s/%d/%s) %s\n", shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), where, expired)
			}
		}
	}
}

// Check the sigs in the msg, get the signer's key (additional query), get the
// rrset from the message, check the signature(s)
func sigCheck(in *dns.Msg, server string, tcp bool) {
	sectionCheck(in.Answer, server, tcp)
	sectionCheck(in.Ns, server, tcp)
	sectionCheck(in.Extra, server, tcp)
}

// Check if there is need for authenticated denial of existence check
func denialCheck(in *dns.Msg) {
	var denial []dns.RR
	// nsec(3) lives in the auth section
	for _, rr := range in.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC {
			return
		}
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			denial = append(denial, rr)
			continue
		}
	}

	if len(denial) > 0 {
		denial3(denial, in)
	}
	fmt.Printf(";+ Unimplemented: check for denial-of-existence for nsec\n")
	return
}

// NSEC3 Helper
func denial3(nsec3 []dns.RR, in *dns.Msg) {
	qname := in.Question[0].Name
	qtype := in.Question[0].Qtype
	switch in.Rcode {
	case dns.RcodeSuccess:
		// qname should match nsec3, type should not be in bitmap
		match := nsec3[0].(*dns.NSEC3).Match(qname)
		if !match {
			fmt.Printf(";- Denial, owner name does not match qname\n")
			fmt.Printf(";- Denial, failed authenticated denial of existence proof for no data\n")
			return
		}
		for _, t := range nsec3[0].(*dns.NSEC3).TypeBitMap {
			if t == qtype {
				fmt.Printf(";- Denial, found type, %d, in bitmap\n", qtype)
				fmt.Printf(";- Denial, failed authenticated denial of existence proof for no data\n")
				return
			}
			if t > qtype { // ordered list, bail out, because not found
				break
			}
		}
		// Some success data printed here
		fmt.Printf(";+ Denial, matching record, %s, (%s) found and type %s denied\n", qname,
			strings.ToLower(dns.HashName(qname, nsec3[0].(*dns.NSEC3).Hash, nsec3[0].(*dns.NSEC3).Iterations, nsec3[0].(*dns.NSEC3).Salt)),
			dns.TypeToString[qtype])
		fmt.Printf(";+ Denial, secure authenticated denial of existence proof for no data\n")
		return
	case dns.RcodeNameError: // NXDOMAIN Proof
		indx := dns.Split(qname)
		var ce string // Closest Encloser
		var nc string // Next Closer
		var wc string // Source of Synthesis (wildcard)
	ClosestEncloser:
		for i := 0; i < len(indx); i++ {
			for j := 0; j < len(nsec3); j++ {
				if nsec3[j].(*dns.NSEC3).Match(qname[indx[i]:]) {
					ce = qname[indx[i]:]
					wc = "*." + ce
					if i == 0 {
						nc = qname
					} else {
						nc = qname[indx[i-1]:]
					}
					break ClosestEncloser
				}
			}
		}
		if ce == "" {
			fmt.Printf(";- Denial, closest encloser not found\n")
			return
		}
		fmt.Printf(";+ Denial, closest encloser, %s (%s)\n", ce,
			strings.ToLower(dns.HashName(ce, nsec3[0].(*dns.NSEC3).Hash, nsec3[0].(*dns.NSEC3).Iterations, nsec3[0].(*dns.NSEC3).Salt)))
		covered := 0 // Both nc and wc must be covered
		for i := 0; i < len(nsec3); i++ {
			if nsec3[i].(*dns.NSEC3).Cover(nc) {
				fmt.Printf(";+ Denial, next closer %s (%s), covered by %s -> %s\n", nc, nsec3[i].Header().Name, nsec3[i].(*dns.NSEC3).NextDomain,
					strings.ToLower(dns.HashName(ce, nsec3[0].(*dns.NSEC3).Hash, nsec3[0].(*dns.NSEC3).Iterations, nsec3[0].(*dns.NSEC3).Salt)))
				covered++
			}
			if nsec3[i].(*dns.NSEC3).Cover(wc) {
				fmt.Printf(";+ Denial, source of synthesis %s (%s), covered by %s -> %s\n", wc, nsec3[i].Header().Name, nsec3[i].(*dns.NSEC3).NextDomain,
					strings.ToLower(dns.HashName(ce, nsec3[0].(*dns.NSEC3).Hash, nsec3[0].(*dns.NSEC3).Iterations, nsec3[0].(*dns.NSEC3).Salt)))
				covered++
			}
		}
		if covered != 2 {
			fmt.Printf(";- Denial, too many, %d, covering records\n", covered)
			fmt.Printf(";- Denial, failed authenticated denial of existence proof for name error\n")
			return
		}
		fmt.Printf(";+ Denial, secure authenticated denial of existence proof for name error\n")
		return
	}
}

// Return the RRset belonging to the signature with name and type t
func getRRset(l []dns.RR, name string, t uint16) []dns.RR {
	var l1 []dns.RR
	for _, rr := range l {
		if strings.ToLower(rr.Header().Name) == strings.ToLower(name) && rr.Header().Rrtype == t {
			l1 = append(l1, rr)
		}
	}
	return l1
}

// Get the key from the DNS (uses the local resolver) and return them.
// If nothing is found we return nil
func getKey(name string, keytag uint16, server string, tcp bool) *dns.DNSKEY {
	c := new(dns.Client)
	if tcp {
		c.Net = "tcp"
	}
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	r, _, err := c.Exchange(m, server)
	if err != nil {
		return nil
	}
	for _, k := range r.Answer {
		if k1, ok := k.(*dns.DNSKEY); ok {
			if k1.KeyTag() == keytag {
				return k1
			}
		}
	}
	return nil
}

// shortSig shortens RRSIG to "miek.nl RRSIG(NS)"
func shortSig(sig *dns.RRSIG) string {
	return sig.Header().Name + " RRSIG(" + dns.TypeToString[sig.TypeCovered] + ")"
}

// shortenMsg walks trough message and shortens Key data and Sig data.
func shortenMsg(in *dns.Msg) {
	for i, answer := range in.Answer {
		in.Answer[i] = shortRR(answer)
	}
	for i, ns := range in.Ns {
		in.Ns[i] = shortRR(ns)
	}
	for i, extra := range in.Extra {
		in.Extra[i] = shortRR(extra)
	}
}

func shortRR(r dns.RR) dns.RR {
	switch t := r.(type) {
	case *dns.DS:
		t.Digest = "..."
	case *dns.DNSKEY:
		t.PublicKey = "..."
	case *dns.RRSIG:
		t.Signature = "..."
	case *dns.NSEC3:
		t.Salt = "." // Nobody cares
		if len(t.TypeBitMap) > 5 {
			t.TypeBitMap = t.TypeBitMap[1:5]
		}
	}
	return r
}
