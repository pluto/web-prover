build:
	-rm -r build
	GOOS=linux GOARCH=amd64 go build -a -o build/vanilla-go-app.linux-amd64 .
	GOOS=darwin GOARCH=arm64 go build -a -o build/vanilla-go-app.darwin-arm64 .

test:
	go test -v -race ./server 

run:
	go run main.go

.PHONY: build test run
