package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const defaultTLSMinVersion = tls.VersionTLS12

func generateSelfSigned(host string) (tls.Certificate, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generate serial: %w", err)
	}

	hostOnly := host
	if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		hostOnly = h
	}

	var dnsNames []string
	var ipAddrs []net.IP
	if hostOnly != "" && hostOnly != "0.0.0.0" && hostOnly != "::" {
		if ip := net.ParseIP(hostOnly); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, hostOnly)
		}
	}
	ipAddrs = appendUniqueIP(ipAddrs, net.ParseIP("127.0.0.1"))
	ipAddrs = appendUniqueIP(ipAddrs, net.ParseIP("::1"))
	dnsNames = appendUniqueStr(dnsNames, "localhost")

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "certhold"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("create certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parse certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
		Leaf:        leaf,
	}, derBytes, nil
}

func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

func appendUniqueIP(list []net.IP, ip net.IP) []net.IP {
	if ip == nil {
		return list
	}
	for _, x := range list {
		if x.Equal(ip) {
			return list
		}
	}
	return append(list, ip)
}

func appendUniqueStr(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
