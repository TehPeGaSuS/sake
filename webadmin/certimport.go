package webadmin

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/TehPeGaSuS/sake/database"
)

// Certificates themselves are imported and generated through the "certfp"
// service commands, so the web admin and IRC accept exactly the same input;
// this file reads the uploaded PEM and formats fingerprints for display.

// maxPEMUpload bounds an uploaded certificate file; a user.pem with a large
// RSA key and a few intermediate certificates is still far below this.
const maxPEMUpload = 64 << 10

// certInfo describes a client certificate for templates.
type certInfo struct {
	SHA256, SHA512 string
}

func newCertInfo(certDER []byte) *certInfo {
	if len(certDER) == 0 {
		return nil
	}
	sha256hex, sha512hex := certFingerprints(certDER)
	return &certInfo{SHA256: sha256hex, SHA512: sha512hex}
}

func certFingerprints(certDER []byte) (sha256hex, sha512hex string) {
	s256 := sha256.Sum256(certDER)
	s512 := sha512.Sum512(certDER)
	return hex.EncodeToString(s256[:]), hex.EncodeToString(s512[:])
}

// uploadedPEM returns the certificate PEM from the file field if a file was
// picked, else from the text field. It's empty if neither was filled in.
func uploadedPEM(r *http.Request, fileField, textField string) (string, error) {
	f, hdr, err := r.FormFile(fileField)
	switch {
	case err == nil:
		defer f.Close()
		if hdr.Size > maxPEMUpload {
			return "", fmt.Errorf("the file is too large for a certificate (max %d KiB)", maxPEMUpload>>10)
		}
		b, err := io.ReadAll(io.LimitReader(f, maxPEMUpload+1))
		if err != nil {
			return "", err
		}
		if len(b) > maxPEMUpload {
			return "", fmt.Errorf("the file is too large for a certificate (max %d KiB)", maxPEMUpload>>10)
		}
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	case errors.Is(err, http.ErrMissingFile), errors.Is(err, http.ErrNotMultipart):
	default:
		return "", err
	}
	return strings.TrimSpace(r.FormValue(textField)), nil
}

// saveAccountCert applies the account certificate part of a form (the
// account page, or an admin's user page): remove, generate or import. It
// reports whether anything changed.
func (h *Handler) saveAccountCert(ctx context.Context, r *http.Request, u *database.User, asAdmin bool) (bool, error) {
	switch r.FormValue("account_cert_action") {
	case "remove":
		if len(u.SASLExternal.CertBlob) == 0 {
			return false, nil
		}
		return true, h.runAs(ctx, u.Username, asAdmin, "certfp", "remove", "-default")
	case "generate":
		return true, h.runAs(ctx, u.Username, asAdmin, "certfp", "generate", "-default")
	}
	pemText, err := uploadedPEM(r, "account_cert_file", "account_cert_pem")
	if err != nil || pemText == "" {
		return false, err
	}
	return true, h.runAs(ctx, u.Username, asAdmin, "certfp", "import", "-default", "--", pemText)
}

// networkCertMode is which client certificate a network presents: "own",
// "account" (the user's default one) or "none".
func networkCertMode(net *database.Network) string {
	switch {
	case len(net.SASL.External.CertBlob) > 0:
		return "own"
	case net.NoDefaultCert:
		return "none"
	default:
		return "account"
	}
}

// usesTLS reports whether a network address connects over TLS, the only
// way a client certificate can be sent. Addresses without a scheme are
// ircs:// (see database.Network.URL).
func usesTLS(addr string) bool {
	scheme, _, ok := strings.Cut(addr, "://")
	return !ok || scheme == "ircs"
}
