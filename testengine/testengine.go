package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	//"net"

	//"strconv"
	"strings"

	//"time"

	//"gopkg.in/yaml.v2"

	"github.com/miekg/dns"
	//"github.com/spf13/viper"
	//"github.com/tolvmannen/digit/dig"
	"github.com/tolvmannen/digit/dig"
)

func (o LabGroups) ShowMe() {
	for _, v := range o.Group {
		fmt.Printf("GroupName: :%s\n", v.GroupName)
		fmt.Printf("Domain: :%s\n", v.Domain)
		fmt.Printf("IPv4: :%s\n", v.IpV4)
		//fmt.Printf("Vdom:%s\n", v.User[0]["name"])
		fmt.Printf("User:\n")
		for _, uv := range v.User {
			fmt.Printf("Name:%s\nKey: %s\n", uv["name"], uv["key"])
		}
		fmt.Printf("\n")
	}
}

func digOutput(dig digResult) {
	r := dig.Result
	e := strings.Join(dig.Extras, "\n")
	fmt.Printf("%s\n%s\n", r, e)

}

func showAll(dig digResult) {

	r := dig.Result
	h := r.MsgHdr
	fmt.Printf("==Response Header==\n")
	fmt.Printf(" Message ID: %v\n", h.Id)
	fmt.Printf(" OPCODE: %v\n", h.Opcode)
	fmt.Printf("--Flags--\n")
	fmt.Printf(" AA: %v\n", h.Authoritative)
	fmt.Printf(" TC: %v\n", h.Truncated)
	fmt.Printf(" RD: %v\n", h.RecursionDesired)
	fmt.Printf(" RA: %v\n", h.RecursionAvailable)
	fmt.Printf(" AD: %v\n", h.AuthenticatedData)
	fmt.Printf(" CD: %v\n", h.CheckingDisabled)
	//fmt.Printf(" (RCODE: %v)\n", h.Rcode)
	fmt.Printf(" (RCODE: %v)\n", dns.RcodeToString[h.Rcode])
	fmt.Printf(" (Zero bit: %v)\n", h.Zero)

	printrr := func(section []dns.RR) {
		for _, rr := range section {
			rf := strings.Fields(rr.String())
			if strings.Contains(rf[0], ";") {
				continue
			}
			on := rf[0]
			ttl := rf[1]
			cl := rf[2]
			ty := rf[3]
			rdata := strings.Join(rf[4:], " ")
			fmt.Printf("\n owner name: %s\n ttl: %s\n class: %s\n type: %s\n rdata: %s\n--\n", on, ttl, cl, ty, rdata)
		}
	}
	if len(r.Answer) > 0 {
		fmt.Printf("\n==RR set in Answer==\n")
		printrr(r.Answer)
	}
	if len(r.Extra) > 0 {
		fmt.Printf("\n==RR set in Extra==\n")
		printrr(r.Extra)
	}
	if len(r.Ns) > 0 {
		fmt.Printf("\n==RR set in Authority==\n")
		printrr(r.Ns)
	}

}

//func mainloop(conf *viper.Viper) {
func mainloop() {
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-exit:
			os.Exit(0)
		}
	}
}

func main() {

	/*
		// Load Group- and Userdata
		grp := viper.New()
		grp.SetConfigFile("./tests/group.yaml")
		err := grp.ReadInConfig()
		if err := grp.ReadInConfig(); err == nil {
			fmt.Fprintln(os.Stderr, "Using config file:", grp.ConfigFileUsed())
		} else {
			fmt.Printf("Error: %v\n", err)
		}

		var lg LabGroups
		err := grp.Unmarshal(&lg)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
		lg.ShowMe()

		conf := viper.New()
		conf.SetConfigFile("./etc/conf.yaml")
		err := conf.ReadInConfig()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}

	*/

	var dp dig.DigParams
	dp = digParams{"qname": "coffee.quiz6.examples.nu"}
	var digdata dig.DigResult
	digdata = dig.Dig(dp)
	fmt.Printf("--\n%v\n--\n", digdata)

	/*

		x := viper.New()
		x.SetConfigFile("./tests/lab.yaml")
		if err := x.ReadInConfig(); err == nil {
			fmt.Fprintln(os.Stderr, "Using config file:", x.ConfigFileUsed())
		} else {
			fmt.Printf("Error: %v\n", err)
		}
		arr := x.GetStringMapString("lab1")

		var batch []digParams
		var dp digParams

		dp = digParams{}
		dp.UpdateFromMapString(arr)
		//para := map[string]string{"qname": "coffee.quiz6.examples.nu"}
		//dp.UpdateFromMapString(para)
		batch = append(batch, dp)

		var digdata digResult

		for _, test := range batch {
			digdata = dig(test)

			showAll(digdata)
			fmt.Printf("\n\n\n")

			// Show as DIG
			//digOutput(digdata)

		}
	*/
}

/*

just for notes...

func initConfig() {
        if cfgFile != "" {
                // Use config file from the flag.
                viper.SetConfigFile(cfgFile)
        } else {
                viper.SetConfigFile(DefaultCfgFile)
        }

        viper.AutomaticEnv() // read in environment variables that match

        // If a config file is found, read it in.
        if err := viper.ReadInConfig(); err == nil {
           if verbose {
                fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
           }
        }
}

*/
