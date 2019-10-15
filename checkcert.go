// Copyright © 2018 Helber Maciel Guerra
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checkcert

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var wg sync.WaitGroup

// HostResult Results
type HostResult struct {
	Host        string
	ExpireDays  int
	Err         error
	Issuer      string
	TLSVersion  string
	ElapsedTime time.Duration
	DNSNames    []string
}

func callHost(domain string, port int, host string) (conn *tls.Conn, err error) {
	ip, err := net.LookupHost(host)
	conn = nil
	if err != nil {
		log.Printf("Could not resolve host name, %v.\n\n", host)
		return
	}
	ipAddressPort := fmt.Sprintf("%s:%d", ip[0], port)
	//Connect network
	ipConn, err := net.DialTimeout("tcp", ipAddressPort, time.Second*2)
	if err != nil {
		log.Printf("Could not connect to %v - %v\n", ipAddressPort, host)
		return
	}
	defer ipConn.Close()
	log.Printf("Connected to %v - %v\n", ipAddressPort, host)
	// Configure tls to look at domain
	config := tls.Config{ServerName: domain}
	// Connect to tls
	conn = tls.Client(ipConn, &config)
	defer conn.Close()
	// Handshake with TLS to get cert
	hsErr := conn.Handshake()
	if hsErr != nil {
		log.Printf("Client connected to: %v\n", conn.RemoteAddr())
		log.Printf("Cert Failed for %v - %v\n", ipAddressPort, domain)
		return
	}
	return
}

// CheckHost check cert
func CheckHost(domain string, port int, host string, res chan<- HostResult) {
	timeNow := time.Now()
	full := fmt.Sprintf("%s:%d:%s", domain, port, host)
	log.Printf("started %s", full)
	result := HostResult{
		Host:       full,
		ExpireDays: -1,
	}
	conn, err := callHost(domain, port, host)
	if err != nil {
		result.Err = err
		result.ElapsedTime = time.Now().Sub(timeNow)
		res <- result
		return
	}
	state := conn.ConnectionState()
	for i, v := range state.PeerCertificates {
		switch i {
		case 0:
			switch v.Version {
			case 0:
				result.TLSVersion = "SSL v3"
			case 1:
				result.TLSVersion = "TLS v1.0"
			case 2:
				result.TLSVersion = "TLS v1.1"
			case 3:
				result.TLSVersion = "TLS v1.2"
				if state.TLSUnique == nil {
					result.TLSVersion = "TLS v1.3"
				}
			}
			result.ExpireDays = int(v.NotAfter.Sub(timeNow).Hours() / 24)
			if len(v.DNSNames) >= 1 {
				result.DNSNames = v.DNSNames
			} else {
				result.DNSNames = []string{v.Subject.CommonName}
			}
			log.Printf("Server key information: {CN:%v, OU:%v, Org:%v, City:%v, State:%v, Country:%v,SSL Cert Valid:{From:%v, To:%v}}\n", v.Subject.CommonName, v.Subject.OrganizationalUnit, v.Subject.Organization, v.Subject.Locality, v.Subject.Province, v.Subject.Country, v.NotBefore, v.NotAfter)
			log.Printf("DNSs=%s\n", result.DNSNames)
		case 1:
			log.Printf("Issued by:{CN:%v, OU:%v, Org:%v}\n", v.Subject.CommonName, v.Subject.OrganizationalUnit, v.Subject.Organization)
			result.Issuer = v.Subject.Organization[0]
		default:
			log.Printf("Ignore: {CN:%v, OU:%v, Org:%v, City:%v, State:%v, Country:%v,SSL Cert Valid:{From:%v, To:%v}}\n", v.Subject.CommonName, v.Subject.OrganizationalUnit, v.Subject.Organization, v.Subject.Locality, v.Subject.Province, v.Subject.Country, v.NotBefore, v.NotAfter)
			log.Printf("Ignore DNSs=%s\n", result.DNSNames)
			break
		}
	}
	result.ElapsedTime = time.Now().Sub(timeNow)
	log.Printf("finished %v in %v", result.Host, result.ElapsedTime)
	res <- result
}

// ParseDomainPortHost parse domain:port:host
func ParseDomainPortHost(info string) (domain string, port int, host string) {
	splt := strings.Split(info, ":")
	port = 443
	if len(splt) > 1 {
		portn, err := strconv.Atoi(splt[1])
		if err == nil {
			port = portn
		}
	}
	domain = splt[0]
	if len(splt) > 2 {
		host = splt[2]
	} else {
		host = domain
	}
	return
}

// CheckHostsParallel Return a slice of host results given some hosts
//
func CheckHostsParallel(hosts ...string) (res []HostResult) {
	results := make(chan HostResult, len(hosts))
	for _, dom := range hosts {
		wg.Add(1)
		domain, port, host := ParseDomainPortHost(dom)
		go CheckHost(domain, port, host, results)
	}
	for range hosts {
		resT := <-results
		log.Println(resT)
		res = append(res, resT)
		wg.Done()
	}
	wg.Wait()
	return
}
