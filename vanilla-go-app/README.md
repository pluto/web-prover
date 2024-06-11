# Vanilla Go App

Potentially useful for establishing baseline benchmarks.
Supports all the HTTP, TCP timeouts and keep alives.

## Usage

```
Usage of ./vanilla-go-app:
  -allow-forced-shutdown
        If second SIGINT or SIGTERM is received, forcefully shutdown immediatly. (default true)
  -connection-draining-timeout duration
        Allow <duration> to gracefully shutdown existing connections (default 5s)
  -http-idle-timeout duration
        IdleTimeout is the maximum amount of time to wait for the next request when keep-alives are enabled. (default 30s)
  -http-keep-alive
        Enable HTTP KeepAlive (default true)
  -http-read-timeout duration
        ReadTimeout is the maximum duration for reading the entire request, including the body. (default 10s)
  -http-write-timeout duration
        WriteTimeout is the maximum duration before timing out writes of the response. (default 10s)
  -listen string
        Listen for connections on host:port (default ":8080")
  -shutdown-delay duration
        After SIGINT or SIGTERM is received, wait <duration> before no more new connections are accepted (default 25s)
  -tcp-idle-timeout duration
        Set <duration> TCP KeepAlive Timeout (default 1m0s)
  -tcp-keep-alive
        Enable TCP KeepAlive (default true)
  -tls-cert-path string
        Serve TLS (cert file)
  -tls-key-path string
        Serve TLS (key file)


./vanilla-go-app -listen :8080
./vanilla-go-app -listen :8080 -tls-cert-path ./cert -tls-key-path ./key

# Returns 200
curl http://localhost:8080

# Returns 200 and fixed size binary body
curl http://localhost:8080/bin/0KB
curl http://localhost:8080/bin/1KB
curl http://localhost:8080/bin/10KB
curl http://localhost:8080/bin/100KB
curl http://localhost:8080/bin/1000KB

# Read and discard the body, returns 204
curl http://localhost:8080/readall -X POST -d 'foobar'

# Reads the body and returns it with status 201
curl http://localhost:8080/echo -X POST -d 'foobar'

# Sleeps for some specified time and returns 202
curl http://localhost:8080/sleep?ms=500 

# Sleeps for some specified time and then closes the TCP connection
curl http://localhost:8080/timeout?ms=500

# Returns 200 and returns request with headers and body as seen by server
curl http://localhost:8080/debug-request

# Returns 200 and dumps request to stdout
curl http://localhost:8080/stdout
```
