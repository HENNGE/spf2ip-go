package main

import (
	context "context"
	"flag"
	"fmt"
	"log"
	net "net"
	"os"

	spf2ip "github.com/HENNGE/spf2ip-go"
)

func main() {
	domain := flag.String("domain", "", "Domain for which the IP addresses should be extracted (required)")
	ipVersion := flag.Int("ip-version", 4, "Define version of IP list to extract (4 or 6; default is 4)")
	debugLogging := flag.Bool("debug", false, "Enable debug logging output to stderr")

	flag.Parse()

	if *domain == "" {
		log.Printf("Usage of spf2ip-go:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *ipVersion != 4 && *ipVersion != 6 {
		log.Fatal("Error: --ip-version must be '4' or '6'")
	}

	resolver := spf2ip.NewSPF2IPResolver(net.DefaultResolver, *debugLogging)

	ips, err := resolver.Resolve(context.Background(), *domain, *ipVersion)
	if err != nil {
		log.Fatalf("Error resolving SPF: %v", err)
	}

	fmt.Printf("Resolved %d IPs for domain %s:\n", len(ips), *domain)

	for _, ip := range ips {
		fmt.Println(ip)
	}
}
