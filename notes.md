Running:
```sh
cargo test --release -- tests::test_end_to_end_proofs --show-output
```

## Benches:
### Full proof with setup
- **Before any changes:** memory usage ~8.25GB on my machine
- **After changes:** TODO

### R1CSWithArity expansion (`get_circuit_shapes`)
- **Long (all circuits):** Hits ~6.5GB
- **Short (just AES-GCM (old)):** Hits ~2GB
