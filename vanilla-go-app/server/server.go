package server

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"time"
)

func Server() *http.ServeMux {
	mux := http.NewServeMux()

	// Default route
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(404)
		} else {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(200) // OK
		}
	})

	// Routes that return fixed KB of binary data
	kb := []int{0, 1, 10, 100, 1000}
	for _, v := range kb {
		b := make([]byte, v*1000)
		_, err := rand.Read(b)
		if err != nil {
			log.Fatal(err)
		}

		mux.HandleFunc("/bin/"+strconv.Itoa(v)+"KB",
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(200) // OK
				w.Write(b)
			})
	}

	// Route that reads full body but discards input
	mux.HandleFunc("/readall", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(204) // No Content
	})

	mux.HandleFunc("/debug-request", func(w http.ResponseWriter, r *http.Request) {
		req, err := httputil.DumpRequest(r, true)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Write(req)
	})

	mux.HandleFunc("/stdout", func(w http.ResponseWriter, r *http.Request) {
		req, err := httputil.DumpRequest(r, true)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		fmt.Fprintln(os.Stdout, string(req)+"\n\n")
		w.WriteHeader(200) // OK
	})

	// Route that reads full body and echos it back to client
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "" {
			w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		w.WriteHeader(201) // Created
		io.Copy(w, r.Body)
		r.Body.Close()
	})

	// Route that will sleep some time
	mux.HandleFunc("/sleep", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		msParam := r.URL.Query().Get("ms")
		ms, err := strconv.Atoi(msParam)
		if err != nil {
			w.WriteHeader(400) // Bad Request
			return
		}
		time.Sleep(time.Duration(ms) * time.Millisecond)
		w.WriteHeader(202) // Accepted
	})

	// Route that will timeout the underlying TCP connection some time
	mux.HandleFunc("/timeout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		msParam := r.URL.Query().Get("ms")
		ms, err := strconv.Atoi(msParam)
		if err != nil {
			w.WriteHeader(400) // Bad Request
			return
		}
		time.Sleep(time.Duration(ms) * time.Millisecond)

		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return
		}

		conn, _, err := hj.Hijack()
		if err != nil {
			w.WriteHeader(500)
			return
		}

		if err := conn.Close(); err != nil {
			panic(err)
		}
	})

	return mux
}

func NewTcpKeepAliveListener(l *net.TCPListener, keepAlive bool, timeout time.Duration) *TcpKeepAliveListener {
	return &TcpKeepAliveListener{l, keepAlive, timeout}
}

// TcpKeepAliveListener is more or less copied from:
// https://github.com/golang/go/blob/release-branch.go1.10/src/net/http/server.go#L3211
type TcpKeepAliveListener struct {
	*net.TCPListener
	KeepAlive bool
	Timeout   time.Duration
}

func (ln TcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(ln.KeepAlive)
	tc.SetKeepAlivePeriod(ln.Timeout)
	return tc, nil
}
