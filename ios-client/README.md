# TLSNotary Static Libary for iOS

This repo contains code for the TLSNotary prover which can be embedded into iOS mobile apps.

## Prerequisites

```
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim

brew install cbindgen # linux: sudo apt install cbindgen
```

Building the iOS libs requires Xcode.


## Usage

```shell
make cbindgen # outputs build/tlsnotary.h header file
make libs # outputs build/tlsnotary-*.a libs
make xcframework # outputs build/tlsnotary.xcframework
```

## Troubleshooting

```
error: tool 'xcodebuild' requires Xcode, but active developer directory '/Library/Developer/CommandLineTools' is a command line tools instance
```

Fix: `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`

## Docs

* https://www.reactnativepro.com/tutorials/integrating-rust-in-a-react-native-project
* https://github.com/fzyzcjy/flutter_rust_bridge
* https://github.com/callstack/react-native-builder-bob/discussions/292#discussioncomment-6489112
* https://ospfranco.com/post/2023/08/11/react-native,-rust-step-by-step-integration-guide/