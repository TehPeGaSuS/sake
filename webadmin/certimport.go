package webadmin

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// Certificates themselves are imported through the "certfp import" service
// command (see handlers.go), so the web admin and IRC accept exactly the
// same input; this file only formats fingerprints for display.

func certFingerprints(certDER []byte) (sha256hex, sha512hex string) {
	s256 := sha256.Sum256(certDER)
	s512 := sha512.Sum512(certDER)
	return hex.EncodeToString(s256[:]), hex.EncodeToString(s512[:])
}
