# localhost cert

**For local development only**

## Add Localhost Root CA to your local Keychain

1. Open the "Keychain Access" Mac app.
2. Drag and drop `ca-cert.cer` into the "System" keychain, and confirm the change with your password.
3. Find the "Localhost Root CA" cert in the "System" keychain and then double click on it. Expand the "Trust" section and "Always Trust" the certificate. Close the window and confirm the change with your password.
4. Restart Chrome.

## Notary keys

```
openssl ecparam -name secp256k1 -genkey -noout -out origo.ec.key
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in origo.ec.key -out origo.key
rm origo.ec.key
openssl ec -in origo.key -pubout -out origo.pub

openssl ecparam -name prime256v1 -genkey -noout -out tlsn.ec.key -outform PEM
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in tlsn.ec.key -out tlsn.key
rm tlsn.ec.key
openssl ec -in tlsn.key -pubout -out tlsn.pub
```
