package soju

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// maxCertKeyFetchSize bounds how much data we'll read when importing a
// certificate and private key, whether from a local file or a URL. PEM
// certs and keys are a few KiB at most.
const maxCertKeyFetchSize = 1 << 20 // 1 MiB

// readCertKeyPEM reads a PEM-encoded certificate and private key
// (concatenated) from a local file path or an https:// URL.
//
// URL fetches reuse the same hardened HTTP client used for Web Push
// (webPushHTTPClient), which refuses to connect to loopback, unspecified,
// multicast, private and link-local addresses, in order to prevent
// server-side request forgery: this command is available to any bouncer
// user, not just admins, since it operates on the caller's own network.
func readCertKeyPEM(ctx context.Context, source string) ([]byte, error) {
	if strings.Contains(source, "://") {
		if !strings.HasPrefix(source, "https://") {
			return nil, fmt.Errorf("only https:// URLs are supported")
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, fmt.Errorf("invalid URL: %v", err)
		}
		resp, err := webPushHTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch %q: %v", source, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to fetch %q: HTTP status %v", source, resp.Status)
		}

		b, err := io.ReadAll(io.LimitReader(resp.Body, maxCertKeyFetchSize+1))
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}
		if len(b) > maxCertKeyFetchSize {
			return nil, fmt.Errorf("response body too large (max %d bytes)", maxCertKeyFetchSize)
		}
		return b, nil
	}

	b, err := os.ReadFile(source)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %q: %v", source, err)
	}
	if len(b) > maxCertKeyFetchSize {
		return nil, fmt.Errorf("file %q too large (max %d bytes)", source, maxCertKeyFetchSize)
	}
	return b, nil
}

// ParseCertKeyPEM parses a PEM blob containing a certificate and a private
// key (concatenated, e.g. as produced by "cat cert.pem key.pem") and
// returns the raw DER certificate and PKCS#8 private key, ready to be
// stored in Network.SASL.External.
func ParseCertKeyPEM(pemBytes []byte) (certDER, privKeyDER []byte, err error) {
	cert, err := tls.X509KeyPair(pemBytes, pemBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate and private key: %v", err)
	}
	if len(cert.Certificate) == 0 {
		return nil, nil, fmt.Errorf("no certificate found")
	}

	privKeyDER, err = x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	return cert.Certificate[0], privKeyDER, nil
}

func generateCertFP(keyType string, bits int) (privKeyBytes, certBytes []byte, err error) {
	var (
		privKey crypto.PrivateKey
		pubKey  crypto.PublicKey
	)
	switch keyType {
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		privKey = key
		pubKey = key.Public()
	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		privKey = key
		pubKey = key.Public()
	case "ed25519":
		var err error
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
	}

	// Using PKCS#8 allows easier extension for new key types.
	privKeyBytes, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	// Lets make a fair assumption nobody will use the same cert for more than 20 years...
	notAfter := notBefore.Add(24 * time.Hour * 365 * 20)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "soju auto-generated certificate"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certBytes, err = x509.CreateCertificate(rand.Reader, cert, cert, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	return privKeyBytes, certBytes, nil
}
