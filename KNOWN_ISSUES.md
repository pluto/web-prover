# Known Issues

#### `error: failed to run custom build command for ring v0.17.8`

You'll have to install LLVM, ie. `brew install llvm`, and then update your
`export PATH="$(brew --prefix)/opt/llvm/bin:$PATH"`.

rust-analyzer might not pick up on the llvm path, you can manually let it know via:

```
# .vscode/settings.json
{
  "rust-analyzer.cargo.extraEnv": {
    "PATH": "<paste your $PATH here>" // note, $PATH env substitutions don't work
  }
}
```

#### `Error: LLVM version must be 18 or higher. Found xxxxxx.`

- Follow instruction at https://apt.llvm.org/

#### `[wasm-validator error in function xxxx] unexpected false: all used features should be allowed, on yyyy`

- Your existing `wasm-opt` installation may conflict with the one in `wasm-pack`. Check for local installation: `$ which wasm-opt && wasm-opt --version`
- Consider updating `wasm-pack`:  `$ cargo install --force wasm-pack`