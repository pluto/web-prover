package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		target := strings.TrimSpace(r.URL.Query().Get("target"))
		if target == "" {
			w.WriteHeader(400)
			w.Write([]byte("no target"))
			log.Println("no ?target")
			return
		}

		log.Printf("New request to %v", target)

		upgrader := websocket.Upgrader{
			ReadBufferSize:  2048,
			WriteBufferSize: 2048,
			CheckOrigin: func(r *http.Request) bool {
				_ = r.Header.Get("Origin")
				// TODO allow: https://localhost:3000, https://docs.pluto.xyz
				return true
			},
		}
		responseHeader := make(http.Header)

		conn, err := upgrader.Upgrade(w, r, responseHeader)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()

		// We are creating an open proxy here. what can possibly go wrong.
		sock, err := net.Dial("tcp", target)
		if err != nil {
			log.Println(err)
			return
		}
		defer sock.Close()

		useBinary := true

		done := make(chan bool, 2)

		go func() {
			defer func() {
				done <- true
			}()

			wbuf := make([]byte, 32*1024)
			for {
				messageType, p, err := conn.ReadMessage()
				if err != nil {
					return
				}

				var fwdbuf []byte

				if messageType == websocket.TextMessage {
					n, _ := base64.StdEncoding.Decode(wbuf, p)
					fwdbuf = wbuf[:n]
				} else if messageType == websocket.BinaryMessage {
					fwdbuf = p
				}

				if fwdbuf != nil {
					_, err = sock.Write(fwdbuf)
					if err != nil {
						return
					}
				}
			}
		}()

		go func() {
			defer func() {
				done <- true
			}()
			rbuf := make([]byte, 8192)
			wbuf := make([]byte, len(rbuf)*2)
			for {
				n, err := sock.Read(rbuf)
				if err != nil {
					return
				}

				if n > 0 {
					var err error

					if useBinary {
						err = conn.WriteMessage(websocket.BinaryMessage, rbuf[:n])
					} else {
						base64.StdEncoding.Encode(wbuf, rbuf[:n])
						err = conn.WriteMessage(websocket.TextMessage, wbuf[:base64.StdEncoding.EncodedLen(n)])
					}

					if err != nil {
						return
					}
				}
			}
		}()
		<-done
	})

	certFile := "../tests/fixture/mock_server/server-cert.pem"
	keyFile := "../tests/fixture/mock_server/server-key.pem"

	port := "8050"

	if certFile != "" || keyFile != "" {
		log.Printf("Listening 0.0.0.0:%v (TLS)", port)
		if err := http.ListenAndServeTLS(fmt.Sprintf("0.0.0.0:%v", port), certFile, keyFile, nil); err != nil {
			panic(err)
		}
	} else {
		log.Printf("Listening 0.0.0.0:%v", port)
		if err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%v", port), nil); err != nil {
			panic(err)
		}
	}
}
