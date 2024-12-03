package main

// docs:
// https://cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources#retrieve_attestation_tokens

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

const (
	TOKEN_TYPE_OIDC        string = "OIDC"
	TOKEN_TYPE_PKI         string = "PKI"
	TOKEN_TYPE_UNSPECIFIED string = "UNSPECIFIED"
)

type CustomTokenRequest struct {
	Audience  string   `json:"audience"`
	TokenType string   `json:"token_type"`
	Nonces    []string `json:"nonces"` // Up to six nonces are allowed. Each nonce must be between 10 and 74 bytes, inclusive.
}

func main() {
	var nonces nonceSlice
	var audience string
	flag.Var(&nonces, "nonce", "specify one or more nonces")
	flag.StringVar(&audience, "audience", "https://notary.pluto.xyz", "specify audience")
	flag.Parse()

	jwt, err := getCustomTokenBytes(CustomTokenRequest{
		Audience:  audience,
		Nonces:    nonces,
		TokenType: TOKEN_TYPE_PKI,
	})
	if err != nil {
		panic(err) // prints to stderr
	}

	out := struct {
		JWT string `json:"jwt"`
	}{
		JWT: string(jwt),
	}
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(out); err != nil {
		panic(err) // prints to stderr
	}

	os.Stdout.Write(buf.Bytes())
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

type nonceSlice []string

func (n *nonceSlice) String() string {
	return fmt.Sprintf("%v", *n)
}

func (n *nonceSlice) Set(value string) error {
	*n = append(*n, value)
	return nil
}
