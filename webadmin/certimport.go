package webadmin

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

// parseClientCertPEM parses a single concatenated PEM blob containing both a
// certificate and a private key - the same one-file format ZNC's cert
// module uses (openssl req -keyout user.pem -x509 -out user.pem) - and
// returns DER-encoded blobs suitable for database.SASL.External.
func parseClientCertPEM(text string) (certDER, keyDER []byte, err error) {
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if certDER == nil {
				certDER = block.Bytes
			}
		case "PRIVATE KEY":
			if keyDER == nil {
				keyDER = block.Bytes // already PKCS#8
			}
		case "RSA PRIVATE KEY":
			if keyDER == nil {
				key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return nil, nil, errors.New("invalid RSA private key: " + err.Error())
				}
				keyDER, err = x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					return nil, nil, err
				}
			}
		case "EC PRIVATE KEY":
			if keyDER == nil {
				key, err := x509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					return nil, nil, errors.New("invalid EC private key: " + err.Error())
				}
				keyDER, err = x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					return nil, nil, err
				}
			}
		}
	}

	if certDER == nil {
		return nil, nil, errors.New("no certificate block found in pasted PEM")
	}
	if keyDER == nil {
		return nil, nil, errors.New("no private key block found in pasted PEM")
	}

	// Sanity-check the key actually parses as PKCS#8 and matches a known type,
	// mirroring what upstream.go expects when it later loads it.
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, nil, errors.New("private key is not valid PKCS#8/PKCS#1/EC: " + err.Error())
	}
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		return nil, nil, errors.New("unsupported private key type")
	}

	if _, err := x509.ParseCertificate(certDER); err != nil {
		return nil, nil, errors.New("invalid certificate: " + err.Error())
	}

	return certDER, keyDER, nil
}

func certFingerprints(certDER []byte) (sha256hex, sha512hex string) {
	s256 := sha256.Sum256(certDER)
	s512 := sha512.Sum512(certDER)
	return hex.EncodeToString(s256[:]), hex.EncodeToString(s512[:])
}
