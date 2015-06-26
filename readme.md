secret-stream
===


```js
var yourPair = cipherStream(curve, yourPrivate, theirPublic);
var theirPair = cipherStream(curve, theirPrivate, yourPublic);
yourPair.secret.pipe(theirPair.secret);
theirPair.secret.pipe(yourPair.secret);

theirPair.plain.on('data', function (d) {
  if (d.toString() === 'hello') {
    theirPair.plain.write('hello yourself');
  }
});
yourPair.plain.on('data', function (d) {
  //'hello yourself'
});
yourPair.plain.write('hello');
```

takes 3 arguments all are optional.

1. elliptical curve type, defaults to secp256k1, other options include secp224r1,
  prime256v1, prime192v1, ed25519, and curve25519.
2. your private ECDH key
3. their public ECDH key

It always creates an ephemeral ECDH key pair to exchange, if you also include
your private long-term identity ECDH key and their public long-term identity ECDH key it will generate the key by
combining

- your ephemeral private key and their ephemeral public key
- your private long-term ECDH key and their ephemeral public key
- your ephemeral private key and their long-term public key

Sses [crypto-stream](https://www.npmjs.com/package/crypto-stream) under the hood
for the actual encryption.

# under no circumstances should this be used for real life things that need to be kept secret

seriously it's for a learning.
