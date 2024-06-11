package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/mattes/vanilla-go-app/server"
)

func main() {
	listenFlag := flag.String("listen", ":8080", "Listen for connections on host:port")
	httpKeepAliveFlag := flag.Bool("http-keep-alive", true, "Enable HTTP KeepAlive")
	httpReadTimeoutFlag := flag.Duration("http-read-timeout", 10*time.Second, "ReadTimeout is the maximum duration for reading the entire request, including the body.")
	httpWriteTimeoutFlag := flag.Duration("http-write-timeout", 10*time.Second, "WriteTimeout is the maximum duration before timing out writes of the response.")
	httpIdleTimeoutFlag := flag.Duration("http-idle-timeout", 30*time.Second, "IdleTimeout is the maximum amount of time to wait for the next request when keep-alives are enabled.")
	tcpKeepAliveFlag := flag.Bool("tcp-keep-alive", true, "Enable TCP KeepAlive")
	tcpIdleTimeoutFlag := flag.Duration("tcp-idle-timeout", 60*time.Second, "Set <duration> TCP KeepAlive Timeout")
	shutdownDelayFlag := flag.Duration("shutdown-delay", 25*time.Second, "After SIGINT or SIGTERM is received, wait <duration> before no more new connections are accepted")
	connectionDrainingTimeoutFlag := flag.Duration("connection-draining-timeout", 5*time.Second, "Allow <duration> to gracefully shutdown existing connections")
	allowForcedShutdownFlag := flag.Bool("allow-forced-shutdown", true, "If second SIGINT or SIGTERM is received, forcefully shutdown immediatly.")
	certFilePathFlag := flag.String("tls-cert-path", "", "Serve TLS (cert file)")
	keyFilePathFlag := flag.String("tls-key-path", "", "Serve TLS (key file)")

	flag.Parse()

	// Register SIGINT and SIGTERM termination calls
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	isShuttingDown := false
	isShuttingDownMu := &sync.RWMutex{}

	mux := server.Server()

	// Health handler
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200) // OK
	})

	// Ready handler
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		isShuttingDownMu.RLock()
		b := isShuttingDown
		isShuttingDownMu.RUnlock()

		w.Header().Set("Content-Type", "text/plain")
		if b {
			w.WriteHeader(503) // Service Unavailable
		} else {
			w.WriteHeader(200) // OK
		}
	})

	httpServer := &http.Server{
		Handler:      mux,
		ReadTimeout:  *httpReadTimeoutFlag,
		WriteTimeout: *httpWriteTimeoutFlag,
		IdleTimeout:  *httpIdleTimeoutFlag,
	}

	// By default, http keep-alives are enabled
	// https://golang.org/pkg/net/http/#Server.SetKeepAlivesEnabled
	if !*httpKeepAliveFlag {
		httpServer.SetKeepAlivesEnabled(false)
	}

	l, err := net.Listen("tcp", *listenFlag)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		log.Println("Start listening", *listenFlag)
		lx := server.NewTcpKeepAliveListener(l.(*net.TCPListener), *tcpKeepAliveFlag, *tcpIdleTimeoutFlag)

		var err error
		if *certFilePathFlag != "" && *keyFilePathFlag != "" {
			err = httpServer.ServeTLS(lx, *certFilePathFlag, *keyFilePathFlag)
		} else {
			err = httpServer.Serve(lx)
		}

		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-shutdown
	log.Println("Shutting down ...")

	isShuttingDownMu.Lock()
	isShuttingDown = true
	isShuttingDownMu.Unlock()

	if *allowForcedShutdownFlag {
		go func() {
			<-shutdown
			log.Fatal("Forced shutdown!")
		}()
	}

	// 1. Delay shutdown
	// This is useful when run inside Docker container with Kubernetes as
	// scheduler for example: Kubernetes will send SIGTERM to let container
	// know that end of life is coming soon, but expect the container to still serve
	// HTTP request until Kubernetes has updated all proxies and the container
	// is finally removed.
	log.Printf("Delaying shutdown by %v", *shutdownDelayFlag)
	time.Sleep(*shutdownDelayFlag)

	// 2. Close all open listeners
	// 3. Close all idle connections

	// 4. Wait up to connectionDrainingTimeoutFlag for existing connections
	//    to return to idle and then shut down
	// 5. After connectionDrainingTimeoutFlag, forcefully shutdown
	// Docs: https://golang.org/pkg/net/http/#Server.Shutdown
	log.Printf("Stop accepting new connections, force shutdown of existing connections in %v", *connectionDrainingTimeoutFlag)
	ctx, cancel := context.WithTimeout(context.Background(), *connectionDrainingTimeoutFlag)
	defer cancel()
	err = httpServer.Shutdown(ctx)
	if err != nil {
		// will log error if there were still existing connections
		// after timeout has passed
		log.Fatalf("Bye. Dirty shutdown, some connections dropped: %v", err)
	}

	log.Println("Bye. Clean shutdown, no connections dropped.")
}
