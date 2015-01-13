// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
)

type dialer func(network, addr string) (net.Conn, error)

func makeDialer(fingerprint []byte, skipCAVerification bool) dialer {

	return func(network, addr string) (net.Conn, error) {
		c, err := tls.Dial(network, addr, &tls.Config{InsecureSkipVerify: skipCAVerification})
		if err != nil {
			return c, err
		}
		connstate := c.ConnectionState()

		keyPinValid := false

		for _, peercert := range connstate.PeerCertificates {
			der, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
			hash := sha256.Sum256(der)
			// 	log.Println(peercert.Issuer)
			// 	log.Printf("%#v", hash)

			if err != nil {
				log.Fatal(err)
			}

			if bytes.Compare(hash[0:], fingerprint) == 0 {
				// log.Println("Pinned Key found")
				keyPinValid = true
			}
		}

		if keyPinValid == false {
			log.Fatal("Key Pin Failed. Certificate Signed with an invalid Public Key")
		}

		return c, nil
	}
}

var transporter Transporter

func setupTransporter() {
	transporter = NewHTTPTransporter(config.Server, config.Tel, registrationInfo.password, config.SkipTLSCheck, config.Fingerprint)
}

type Response struct {
	Status int
	Body   io.ReadCloser
}

func (r *Response) isError() bool {
	return r.Status < 200 || r.Status >= 300
}

func (r *Response) Error() string {
	return fmt.Sprintf("Status code %d\n", r.Status)
}

type Transporter interface {
	Get(url string) (*Response, error)
	PutJSON(url string, body []byte) (*Response, error)
	PutBinary(url string, body []byte) (*Response, error)
}

type HTTPTransporter struct {
	baseURL string
	user    string
	pass    string
	client  *http.Client
}

func NewHTTPTransporter(baseURL, user, pass string, skipTLSCheck bool, keyFingerprint string) *HTTPTransporter {
	client := &http.Client{}
	fingerprint, err := hex.DecodeString(keyFingerprint)
	if err != nil {
		log.Fatal(err)
	}
	client.Transport = &http.Transport{
		DialTLS: makeDialer(fingerprint, skipTLSCheck),
	}

	return &HTTPTransporter{baseURL, user, pass, client}
}

func (ht *HTTPTransporter) Get(url string) (*Response, error) {
	req, err := http.NewRequest("GET", ht.baseURL+url, nil)
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	r := &Response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	if r.isError() {
		log.Printf("GET %s %d\n", url, r.Status)
	}

	return r, err
}

func (ht *HTTPTransporter) put(url string, body []byte, ct string) (*Response, error) {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PUT", ht.baseURL+url, br)
	req.Header.Add("Content-type", ct)
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	r := &Response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	if r.isError() {
		log.Printf("PUT %s %d\n", url, r.Status)
	}

	return r, err
}

func (ht *HTTPTransporter) PutJSON(url string, body []byte) (*Response, error) {
	return ht.put(url, body, "application/json")
}

func (ht *HTTPTransporter) PutBinary(url string, body []byte) (*Response, error) {
	return ht.put(url, body, "application/octet-stream")
}
