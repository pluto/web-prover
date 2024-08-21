# Setting up in this repo
To create a new circomkit repo in here, I ran:
```
circomkit init proofs
cd proofs && rm -rf .git && cd ..
```
so that we make a directory that is managed by `web-prover` repo.
Then I stepped into `./proofs` manually to remove some unnecessary files and directories.
I left a few because they could be useful.

## Working with this
To get everything up and running I did:
```
cd proofs
npm install
```
Likely some of this can be brought out to repo root, but this is fine for now.