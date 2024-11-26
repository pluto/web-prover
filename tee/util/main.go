package main

// docs:
// https://cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources#retrieve_attestation_tokens

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/google/go-attestation/attest"
)

const (
	TOKEN_TYPE_OIDC        string = "OIDC"
	TOKEN_TYPE_UNSPECIFIED string = "UNSPECIFIED"
	// TODO: PKI?
)

type CustomTokenRequest struct {
	Audience  string   `json:"audience"`
	TokenType string   `json:"token_type"`
	Nonces    []string `json:"nonces"` // Up to six nonces are allowed. Each nonce must be between 10 and 74 bytes, inclusive.
}

func main() {
	customToken, err := getCustomTokenBytes(CustomTokenRequest{
		Audience:  "http://audience",                                      // TODO
		Nonces:    []string{"0000000000000000000", "0000000000000000001"}, // TODO
		TokenType: TOKEN_TYPE_OIDC,
	})
	if err != nil {
		panic(err)
	}

	// ---

	config := &attest.OpenConfig{
		// TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		panic(err)
	}
	defer tpm.Close()

	eks, err := tpm.EKs()
	if err != nil {
		panic(eks)
	}

	// ---
	// debug out
	out := struct {
		CustomToken string
		EKS         []attest.EK
	}{
		CustomToken: string(customToken),
		EKS:         eks,
	}

	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(out); err != nil {
		panic(err)
	}

	fmt.Println(buf.String())
}

func getCustomTokenBytes(request CustomTokenRequest) ([]byte, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/run/container_launcher/teeserver.sock")
			},
		},
	}

	j, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request json: %w", err)
	}

	resp, err := httpClient.Post("http://localhost/v1/token", "application/json", bytes.NewReader(j))
	if err != nil {
		return nil, fmt.Errorf("failed to get raw token response: %w", err)
	}
	defer resp.Body.Close()

	tokenbytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token body: %w", err)
	}

	return bytes.TrimSpace(tokenbytes), nil
}

// ------

// EK is a burned-in endorcement key bound to a TPM. This optionally contains
// a certificate that can chain to the TPM manufacturer.
// type EK struct {
// 	// Public key of the EK.
// 	Public crypto.PublicKey

// 	// Certificate is the EK certificate for TPMs that provide it.
// 	Certificate *x509.Certificate

// 	// For Intel TPMs, Intel hosts certificates at a public URL derived from the
// 	// Public key. Clients or servers can perform an HTTP GET to this URL, and
// 	// use ParseEKCertificate on the response body.
// 	CertificateURL string

// 	// The EK persistent handle.
// 	handle tpmutil.Handle
// }
