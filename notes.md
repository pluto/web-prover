# Notes
To do codgen I did:
```
pabuild json --template node_modules/parser-attestor/examples/json/lockfile/two_keys.json --output-filename test  
```
which I then had to edit the `include` statement to be:
```
include "parser-attestor/circuits/json/interpreter.circom";
```

- 
- Okay I had to comment out the `Slice` function in our `parser-attestor` node modules