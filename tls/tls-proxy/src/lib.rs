use std::collections::HashMap;

pub struct OrigoConnection {
    secret_map: HashMap<String, Vec<u8>>,
}

impl OrigoConnection {
    pub fn new() -> OrigoConnection {
        return {
            OrigoConnection {
                secret_map: HashMap::new(),
            }
        };
    }

    pub fn set_secret(self: &Self, name: String, val: Vec<u8>) {
        // Part 1 ==
        // 1. "DHE" - Record the key from the handshake (sharedKey)
        // 2. "ES" - Early secret (potentially the randomness?)
        // 3. "DES" - "Derived" early secret ("DES", uses early secret)
        // 4. "DHTS" - "Derived" Handshake Traffic Secret (uses DES and shared key)
        // 5. "CHTS" Client Handshake Traffic Secret (mixes 4 with handshake transcript and "client" label)

        // Part 2 ==
        // 1. "SHTS" - Server Handshake Traffic Secret (mixes 4, handshake transcript and "server" label)
        // 2. "H2" - record the transcript hash
        // 3. "dhS" - "Derived" Handshake Secret ()
        // 4. "MS" - "Master Secret", extracted from DHS.
    }
}
