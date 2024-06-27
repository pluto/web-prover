# localhost cert

__For local development only__

## Add Localhost Root CA to your local Keychain
1. Open the "Keychain Access" Mac app.
2. Drag and drop `ca-cert.cer` into the "System" keychain, and confirm the change with your password.
3. Find the "Localhost Root CA" cert in the "System" keychain and then double click on it. Expand the "Trust" section and "Always Trust" the certificate. Close the window and confirm the change with your password.
4. Restart Chrome.
