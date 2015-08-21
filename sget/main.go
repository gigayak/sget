package main

import (
	"crypto/tls"
	"crypto/x509"
	//"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	//"net/url"
	"os"
)

var (
	stdout = flag.Bool("O-", false,
		"Whether to save to stdout")
	_ = flag.Bool("retry-connrefused", false,
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
	/*
	proxyURL, err := url.Parse(*proxyAddr)
	if err != nil {
		log.Fatalf("Failed to parse proxy address %q: %v", *proxyAddr, err)
	}
	log.Printf("Proxying via %q", proxyURL.String())
	*/
	dialTLS := func (network, addr string) (net.Conn, error) {
		// dialTLS("tcp", "repo.jgilik.com:443"
		log.Printf("Got dialTLS(%q, %q)", network, addr)
		return net.Dial(network, *proxyAddr)
		//return nil, errors.New("have not yet implemented glorious hostname override in dialTLS function - pretend to be dialing based on hostname here, but actually contact proxyURL")
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialTLS: dialTLS,
		//Proxy: http.ProxyURL(proxyURL),
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
	// Forcibly coerce to HTTPS scheme so DialTLS is used.
	// This allows HTTPS proxy to be used.
	//req.URL.Scheme = "https"
	/*
	log.Printf("Setting host to %q", req.URL.Host)
	req.Host = req.URL.Host
	req.Header.Set("Host", req.URL.Host)
	req.URL.Host = *proxyAddr
	log.Printf("URL Host is %q", req.URL.Host)
	log.Printf("Header Host is %q", req.Host)
	*/
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("GET failed for URL %q: %v", url, err)
	}
	log.Printf("Completed request.")
	if *stdout {
		buf := make([]byte, 512, 512)
		for {
			n, err := resp.Body.Read(buf)
			os.Stdout.Write(buf[0:n])
			if err == io.EOF {
				return
			} else if err != nil {
				log.Fatalf("Error reading response body: %v", err)
			}
		}
	} else {
		log.Fatalf("Currently only stdout output is supported")
	}
}
