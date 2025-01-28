
# IOS Test Harness

*Overview*
This directory contains an iOS testing harness that can be run on osx and ios. Under the hood our client libraries can be built as a staticlib and c bindings are exposed via FFI. This enables the library to be linked with an iOS application build. 

The primary method for xcode to link external libraries is via a concept called XCFramework.  We generate an XCFramework when building for iOS, it is stored in the `target/aarch64-apple-ios/release` directory.  See the makefile for more details. 

*Usage* 
1. Ensure xcode is installed
2. Setup local notary via the notary docs
3. Open xcode and the `client_ios/demo` project
4. Run `make ios-sim` if running in the simulator, or `make ios` for on device testing
5. Run `make wasm-demo` to temporarily host the artifact
6. Click demo in the upper left `Signing and Capabilities > Login` input personal cred (talk to matt to register)
7. Select `Pluto Development` as the signing organization
8. Return to xcode and select `Product > Run` or `cmd+R`
9. Click `setup tracing` to enable logging, then `generate proof`

## Advanced Notes

*Module Map Files*
XCode relies on a concept called [modules](https://clang.llvm.org/docs/Modules.html#introduction) which use a modulemap file to describe the connection between a standalone C library and a swift or objective-c application. 

Web prover use a default module map file which simply exposes are library as a framework called `Prover`, exposed c-bindings can be called on this interface. 


*Linking dependencies*
Our static library depends on the `-lstdc++` or `-lc++` library, link either when using xcode. The default project settings in the demo harness should already link this library. 

If it has not been linked, you may see a linking error such as: 
`error build: Undefined symbol: std::exception::what() const`

To remedy: 
1. Open xcode
2. Select Demo > Build Settings > Other Linker Flags
3. Click `+` and add `-lstdc++` as a flag


*Listing linking dependencies*
The rust compiler has a special flag `--print=native-static-libs` for listing the linking dependencies of a static library. This can be helpful for identifying missing linker flags. 

To use:
1. Run `cargo clean` (the command only works when rustc builds)
2. Prepend `RUSTFLAGS="--print=native-static-libs"` to the cargo build command for the ios target.
3. Search for `native-static-libs:` to view a list of linker flags

For example, this output was shown at testing time:
`note: native-static-libs: -framework Security -framework CoreFoundation -lc++ -liconv -lSystem -lc -lm`

Most of these appears to already be linked by xcode, but `-lc++` in particular was missing. 


*Local certificate chain*
The demo harness has been setup to work with localhost services using TLS, this requires loading a certificate into the TLS client. It currently relies on the `demo/ca-cert.cer`, this is identical to the certificate in the fixtures directory.

If that certificate changes, both will need updated. 