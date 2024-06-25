# TLSN WASM Demo
## To build this module:

```
# install wasm-pack wasm compilation toolchain if not already installed
#wasm-pack docs https://rustwasm.github.io/wasm-pack/book/quickstart.html
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# install wasm as a compilation target if not already installed
rustup target add wasm32-unknown-unknown

# build this module with wasm-pack
wasm-pack build --target web
```

## Special instructions for OSX Build
Double check clang support for wasm
```clang --print-targets | grep -i wasm```

If not, install llvm for wasm build target with clang on OSX
```brew install llvm```

Then, check again.
```PATH="/opt/homebrew/opt/llvm/bin:$PATH" clang --print-targets | grep -i wasm```

Now, build with the new clang
```PATH="/opt/homebrew/opt/llvm/bin:$PATH" wasm-pack build --target web```

This module may be simply checked as usual with `cargo check`.

## To run the Golang vanilla server:

```shell
cd websocket-proxy
go run main.go -listen 0.0.0.0:8050 \
  -tls-cert-path ../vanilla-go-app/certs/server-cert.pem \
  -tls-key-path ../vanilla-go-app/certs/server-key.pem

cd vanilla-go-app
go run main.go -listen 0.0.0.0:8065 \
  -tls-cert-path ./certs/server-cert.pem \
  -tls-key-path ./certs/server-key.pem \
  -http-read-timeout 5m -http-write-timeout 5m

cargo run -p notary-server -- --config-file ./notary-config.yaml
```

```
npm install
npm run start
open https://localhost:8090
```

TODO: It's possible to run headless tests, which could be interesting for some unit tests.
