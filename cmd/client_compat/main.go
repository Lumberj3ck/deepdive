package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type testCase struct {
	domain string
	qtype  uint16
}

func parseTypes(value string) ([]uint16, error) {
	var types []uint16
	for _, value := range strings.Split(value, ",") {
		name := strings.ToUpper(strings.TrimSpace(value))
		qtype, ok := dns.StringToType[name]
		if !ok {
			return nil, fmt.Errorf("unknown record type %q", value)
		}
		types = append(types, qtype)
	}
	if len(types) == 0 {
		return nil, errors.New("at least one record type is required")
	}
	return types, nil
}

func loadTestCases(path string, defaultTypes []uint16) ([]testCase, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cases []testCase
	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 1 || len(fields) > 2 {
			return nil, fmt.Errorf("%s:%d: expected domain and optional record type", path, lineNumber)
		}
		domain := dns.Fqdn(fields[0])
		if _, valid := dns.IsDomainName(domain); !valid {
			return nil, fmt.Errorf("%s:%d: invalid domain %q", path, lineNumber, fields[0])
		}

		types := defaultTypes
		if len(fields) == 2 {
			qtype, ok := dns.StringToType[strings.ToUpper(fields[1])]
			if !ok {
				return nil, fmt.Errorf("%s:%d: unknown record type %q", path, lineNumber, fields[1])
			}
			types = []uint16{qtype}
		}
		for _, qtype := range types {
			cases = append(cases, testCase{domain: domain, qtype: qtype})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("%s: no domains found", path)
	}
	return cases, nil
}

func exchange(client *dns.Client, server string, tc testCase, checkingDisabled bool) (*dns.Msg, time.Duration, error) {
	request := new(dns.Msg)
	request.SetQuestion(tc.domain, tc.qtype)
	request.CheckingDisabled = checkingDisabled
	request.SetEdns0(1232, false)
	return client.Exchange(request, server)
}

func recordsEqual(left, right []dns.RR) bool {
	if len(left) != len(right) {
		return false
	}

	matched := make([]bool, len(right))
	for _, leftRecord := range left {
		found := false
		for index, rightRecord := range right {
			if !matched[index] && dns.IsDuplicate(leftRecord, rightRecord) {
				matched[index] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func responsesEqual(left, right *dns.Msg) bool {
	return left.Rcode == right.Rcode &&
		recordsEqual(left.Answer, right.Answer)
}

func printResponse(label string, response *dns.Msg, elapsed time.Duration, err error) {
	fmt.Printf("%s duration=%s", label, elapsed)
	if err != nil {
		fmt.Printf(" error=%v\n", err)
		return
	}
	fmt.Printf("\n%s\n", strings.TrimSpace(response.String()))
}

func main() {
	server := flag.String("server", "127.0.0.1:5356", "DeepDive DNS server")
	reference := flag.String("reference", "8.8.8.8:53", "Reference DNS server")
	domainsFile := flag.String("domains", "cmd/client_compat/domains.txt", "Domains file; lines may include an optional record type")
	typeNames := flag.String("types", "A,AAAA,MX", "Comma-separated types used for lines without an explicit type")
	timeout := flag.Duration("timeout", 5*time.Second, "Timeout for each DNS request")
	checkingDisabled := flag.Bool("cd", true, "Set the checking-disabled flag to avoid reference DNSSEC validation differences")
	flag.Parse()

	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "timeout must be greater than zero")
		os.Exit(2)
	}
	for _, address := range []string{*server, *reference} {
		if _, _, err := net.SplitHostPort(address); err != nil {
			fmt.Fprintf(os.Stderr, "invalid server address %q: %v\n", address, err)
			os.Exit(2)
		}
	}

	defaultTypes, err := parseTypes(*typeNames)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid types: %v\n", err)
		os.Exit(2)
	}
	cases, err := loadTestCases(*domainsFile, defaultTypes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load domains: %v\n", err)
		os.Exit(2)
	}

	client := &dns.Client{Net: "udp", Timeout: *timeout}
	mismatches := 0
	for _, tc := range cases {
		deepDiveResponse, deepDiveDuration, deepDiveErr := exchange(client, *server, tc, *checkingDisabled)
		referenceResponse, referenceDuration, referenceErr := exchange(client, *reference, tc, *checkingDisabled)
		if deepDiveErr == nil && referenceErr == nil && responsesEqual(deepDiveResponse, referenceResponse) {
			continue
		}

		mismatches++
		fmt.Printf("\nMISMATCH %s %s\n", tc.domain, dns.TypeToString[tc.qtype])
		printResponse("deepdive", deepDiveResponse, deepDiveDuration, deepDiveErr)
		printResponse("reference", referenceResponse, referenceDuration, referenceErr)
	}

	typeLabels := make([]string, 0, len(defaultTypes))
	for _, qtype := range defaultTypes {
		typeLabels = append(typeLabels, dns.TypeToString[qtype])
	}
	sort.Strings(typeLabels)
	fmt.Printf("\nCompared %d queries against %s (default types: %s); mismatches: %d\n", len(cases), *reference, strings.Join(typeLabels, ","), mismatches)
	if mismatches > 0 {
		os.Exit(1)
	}
}
