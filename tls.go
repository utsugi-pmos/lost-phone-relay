// SPDX-License-Identifier: GPL-2.0-or-later
//
// TLS with an own certificate, generated the first time and reused afterwards.
//
// WHY NOT LET'S ENCRYPT
// ---------------------
// Because this relay is reached by IP and port, without a domain, which is how
// whoever uses it wants it and is a legitimate choice: setting this up should not
// require buying a domain. And a public authority does not sign a home IP.
//
// WHY NOT PLAIN HTTP
// ------------------
// Because as soon as the port is opened on the router, the panel password and the
// phone's token cross the internet. In the clear that is handing them to anyone
// on the path.
//
// HOW A CERTIFICATE WITH NO AUTHORITY IS TRUSTED
// ----------------------------------------------
// Like in SSH: you pin the one you saw the FIRST time. The phone keeps the
// certificate's fingerprint during pairing -- which is the moment there is already
// a shared secret, the four-digit code -- and from then on only accepts that one.
// An attacker who interposes AFTERWARDS presents a different certificate and is
// rejected; to slip in they would have to be there already during pairing.
//
// The browser does warn the first time, and the exception has to be accepted. It
// is ugly and it is honest: there is no way for a browser to trust a self-signed
// certificate without someone saying yes.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Ten years. A certificate that expires is a relay that one day stops working
// without anyone having touched anything, and that would happen precisely on the
// day you lose the phone.
const certValidity = 10 * 365 * 24 * time.Hour

// Returns the paths of the certificate and the key, generating them if they do
// not exist. The SHA-256 fingerprint is returned too: it is what has to be typed
// -- or better, what the phone keeps when pairing.
func ensureCert(dataDir string) (certPath, keyPath, fingerprint string, err error) {
	certPath = filepath.Join(dataDir, "cert.pem")
	keyPath = filepath.Join(dataDir, "key.pem")

	if _, statErr := os.Stat(certPath); statErr == nil {
		fp, fpErr := certFingerprint(certPath)
		return certPath, keyPath, fp, fpErr
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "lost-phone-relay"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	// All of the machine's addresses, because it is unknown which one it will be
	// reached by: the home one today, the public one tomorrow.
	template.DNSNames = []string{"lost-phone-relay", "localhost"}
	template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if addresses, e := net.InterfaceAddrs(); e == nil {
		for _, d := range addresses {
			if netw, ok := d.(*net.IPNet); ok && !netw.IP.IsLoopback() {
				template.IPAddresses = append(template.IPAddresses, netw.IP)
			}
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", "", err
	}
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", "", "", err
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return "", "", "", err
	}

	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", "", err
	}
	// 0600: nobody else reads the private key.
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", "", err
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}); err != nil {
		return "", "", "", err
	}

	sum := sha256.Sum256(der)
	return certPath, keyPath, readableFingerprint(sum[:]), nil
}

func certFingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("%s is not a PEM certificate", certPath)
	}
	sum := sha256.Sum256(block.Bytes)
	return readableFingerprint(sum[:]), nil
}

// AA:BB:CC:... in uppercase, which is how everyone shows it and how it can be
// compared at a glance with the one a browser displays.
func readableFingerprint(sum []byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(parts, ":")
}
