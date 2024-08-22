## TESTING

For testing the cryptography backend with a server, these various snippets can be useful. 

*Pinning the master secret & handshake Hash*
Enables one to override the master secret and handshake hash to test encrypt/decrypt. 

add to: src/client/tls13.rs#handle_server_hello
```
let old_pms = cx.common.backend.get_master_secret().await.unwrap();

let ms = hex::decode("5422bf3f87da4716b915a823b31eeb90d44eb7ba65458ad1bb8757e2cbf31d0a").unwrap();
let arr: [u8; 32] = ms[..32].try_into().unwrap();
let _ = cx.common.backend.set_master_secret(arr).await;

// Traffic key hash
let handshake_hash = hex::decode("d74e203494c2a74b968a4d94f0048d121f1bd7019201af1fafeec380ce4c5c4c").unwrap();
warn!("UPDATED HANDSHAKE HASH hash={:?}", handshake_hash);

cx.common
    .backend.set_hs_hash_client_key_exchange(handshake_hash)
    .await?;

// reset the sequence. 
cx.common
    .backend
    .set_encrypt(EncryptMode::Application)
    .await?;

cx.common
    .backend
    .set_decrypt(DecryptMode::Application)
    .await?;

// CALL ENCRYPT WITH PLAINTEXT HASH
let ct = hex::decode("b2ecd8b347b4cc4906d014c48b1eb5ce5f1352aff88b1f8e2b42d9").unwrap();
let _ = cx.common.backend.decrypt(OpaqueMessage{
    typ: ContentType::ApplicationData,
    version: ProtocolVersion::TLSv1_2,
    payload: Payload(ct)
}, 0).await;

let pt = hex::decode("14000020306b1457f73a23ccd3747cffaf234a05b176c49fdfd36e1408839969d4a5672f").unwrap();
let _ = cx.common.backend.encrypt(PlainMessage{
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_3,
    payload: Payload(pt)
}, 0).await;


cx.common.record_layer.set_message_encrypter();
cx.common.record_layer.set_message_decrypter();
```


*Pinning the keypair in ECDH*
Use to pin the keypair used in ECDH 

```
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
let seed: [u8; 32] = [0; 32]; 
let mut rng = ChaCha20Rng::from_seed(seed);

let client_sk = EphemeralSecret::random(&mut rng);
let pk_bytes = EncodedPoint::from(client_sk.public_key()).to_bytes().to_vec();
self.ecdh_pubkey = Some(pk_bytes.clone());
self.ecdh_secret = Some(client_sk);
warn!("setting client_pk={:?}", hex::encode(pk_bytes));

let server_sk = EphemeralSecret::random(&mut rng);
let server_pk = ECDHPublicKey::from_sec1_bytes(
    &EncodedPoint::from(server_sk.public_key()).to_bytes()
).map_err(|_| BackendError::InvalidServerKey)?;
warn!("setting server_pk={:?}", hex::encode(EncodedPoint::from(server_sk.public_key()).to_bytes()));
```