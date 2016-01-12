package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
)

var (
	stdout = flag.Bool("O-", false,
		"Whether to save to stdout")
	_ = flag.Bool("retry-connrefused", false,
		"non-operation; exists for wget compatibility")
	_ = flag.Bool("q", false,
		"non-operation; exists for wget compatibility")
	keyPath = flag.String("key", "/opt/ssl/client.key",
		"Private key for client certificate.")
	certPath = flag.String("cert", "/opt/ssl/client.crt",
		"Client certificate file.")
	caPath = flag.String("ca", "/opt/ssl/ca.crt",
		"Certificate authority certificate file.")
	proxyAddr = flag.String("proxy", "proxy.jgilik.com:443",
		"'hostname:port' of HTTPS proxy to connect through.")
)

func main() {
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("Failed to read client certificate %q and key %q: %v",
			*certPath, *keyPath, err)
	}

	ca, err := ioutil.ReadFile(*caPath)
	if err != nil {
		log.Fatalf("Failed to read CA certificate %q: %v", *caPath, err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs: caPool,
	}
	dialTLS := func (network, addr string) (net.Conn, error) {
		return tls.Dial(network, *proxyAddr, tlsConfig)
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialTLS: dialTLS,
	}
	client := &http.Client{
		Transport: transport,
	}

	urls := flag.Args()
	if len(urls) != 1 {
		log.Fatalf("Incorrect number of URLs: got %d; want 1", len(urls))
	}
	url := urls[0]
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Failed to construct request for URL %q", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("GET failed for URL %q: %v", url, err)
	}
	if *stdout {
		buf := make([]byte, 512, 512)
		for {
			n, err := resp.Body.Read(buf)
			os.Stdout.Write(buf[0:n])
			if err == io.EOF {
				break
			} else if err != nil {
				log.Fatalf("Error reading response body: %v", err)
			}
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			log.Fatalf("Received error code %d", resp.StatusCode)
		}
	} else {
		log.Fatalf("Currently only stdout output is supported")
	}
}
