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

	fmt.Println(string(customToken))
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
