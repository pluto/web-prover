Running:
```sh
cargo test --release -- tests::test_end_to_end_proofs --show-output
```

## Benches:
### Full proof with setup
- **Before any changes:** memory usage ~8.25GB on my machine
- **After changes:** peak usage ~4GB (with the 440K constraint version of aes i believe)

### R1CSWithArity expansion (`get_circuit_shapes`)
- **Long (all circuits):** Hits ~6.5GB
- **Short (just AES-GCM (old)):** Hits ~2GB

---

Some summaries:
- Did a janky rework of the `program::run()` so that we can only cache the currently used circuit in the `PublicParams`. This led me to just comment out a bunch of things so that this would compile and work.
- The way of deploying the currently used circuit is definitely inefficient, but this was done mostly to just see if this works. Given the above memory reduction, it does seem to be fine.