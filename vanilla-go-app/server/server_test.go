package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func request(method, url string, body []byte) (r *http.Response, responseBody []byte) {
	req := httptest.NewRequest(method, url, bytes.NewReader(body))
	w := httptest.NewRecorder()
	Server().ServeHTTP(w, req)
	resp := w.Result()
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, respBody
}

func TestServer_DefaultRoute(t *testing.T) {
	resp, body := request("GET", "/", nil)
	if resp.StatusCode != 200 {
		t.Error()
	}
	if resp.Header.Get("Content-Type") != "text/plain" {
		t.Error()
	}
	if len(body) > 0 {
		t.Error()
	}
}

func TestServer_404(t *testing.T) {
	resp, _ := request("GET", "/bogus", nil)
	if resp.StatusCode != 404 {
		t.Error()
	}
}

func TestServer_FixedByteRoute(t *testing.T) {
	resp, body := request("GET", "/bin/10KB", nil)
	if resp.StatusCode != 200 {
		t.Error()
	}
	if resp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Error()
	}
	if len(body) != 10*1000 {
		t.Error()
	}
}

func TestServer_ReadAllRoute(t *testing.T) {
	resp, body := request("POST", "/readall", []byte("foobar"))
	if resp.StatusCode != 204 {
		t.Error()
	}
	if resp.Header.Get("Content-Type") != "text/plain" {
		t.Error()
	}
	if len(body) > 0 {
		t.Error()
	}
}

func TestServer_EchoRoute(t *testing.T) {
	in := []byte("foobar")
	resp, body := request("POST", "/echo", in)
	if resp.StatusCode != 201 {
		t.Error()
	}
	if resp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Error()
	}
	if len(body) != len(in) {
		t.Error()
	}
	if !bytes.Equal(body, in) {
		t.Error()
	}
}

func TestServer_SleepRoute(t *testing.T) {
	t0 := time.Now()
	resp, body := request("GET", "/sleep?ms=200", nil)
	t1 := time.Now()

	if resp.StatusCode != 202 {
		t.Error()
	}
	if resp.Header.Get("Content-Type") != "text/plain" {
		t.Error()
	}
	if len(body) > 0 {
		t.Error()
	}
	if t1.Sub(t0) < 200*time.Millisecond {
		t.Errorf("took %v", t1.Sub(t0))
	}
}

func TestServer_DebugRequest(t *testing.T) {
	resp, body := request("GET", "/debug-request", nil)
	if resp.StatusCode != 200 {
		t.Error()
	}

	if !bytes.Contains(body, []byte("GET /debug-request HTTP/1.1")) {
		t.Errorf("expected dumped request, got:\n%s", body)
	}
}
