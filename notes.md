To get iOS to work:

1. `cd proofs && make circuits && cd ..`
2. `make ios-sim`
2. `make wasm && make wasm-demo` (Maybe needed for now?)
3. `RUST_LOG=debug cargo run --release -p notary -- --config ./fixture/notary-config.toml`

---

Witness stuff:
- Still requiring that the FFI for AES-GCM-fold witness-rs is there. It is hardcoded somewhere, don't know where yet. Thing still builds though so whatever on this for now. Worth coming back to though.
- We are still using a wasm witgen reference? Perhaps it is just a dummy thing? But it is causing this error:
```
thread '<unnamed>' panicked at proofs/src/circom/witness.rs:108:51:
called `Result::unwrap()` on an `Err` value: Os { code: 30, kind: ReadOnlyFilesystem, message: "Read-only file system" }
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```
as far as I can tell. Going to get rid of this now.
- I am also referencing changes I made previously in [this](https://github.com/pluto/web-prover/pull/228/files).
- `// TODO: Dedup origo_native and origo_wasm. The difference is the witness/r1cs preparation.` in `client::origo_native` is a good issue to make.
- Using witnesscalc is a little troublesome. I think we NEED to build bin with our fork and use our fork in this for CI (for now). Worth investigating this further though. From what I can tell, this is the case. It is advisable to then tell everyone to use our fork when installing this.