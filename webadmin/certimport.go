package webadmin

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"

	sake "github.com/TehPeGaSuS/sake"
)

// parseClientCertPEM parses a single concatenated PEM blob containing both a
// certificate and a private key - the same one-file format ZNC's cert
// module uses (openssl req -keyout user.pem -x509 -out user.pem) - and
// returns DER-encoded blobs suitable for database.SASL.External. It shares
// its implementation with the "certfp import" service command so the web
// admin and the IRC service command accept exactly the same input.
func parseClientCertPEM(text string) (certDER, keyDER []byte, err error) {
	return sake.ParseCertKeyPEM([]byte(text))
}

func certFingerprints(certDER []byte) (sha256hex, sha512hex string) {
	s256 := sha256.Sum256(certDER)
	s512 := sha512.Sum512(certDER)
	return hex.EncodeToString(s256[:]), hex.EncodeToString(s512[:])
}
