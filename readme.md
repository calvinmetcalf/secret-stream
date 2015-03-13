cipher stream
===

A cipher stream,


```js
var yourPair = cipherStream(yourPrivate, theirPublic);
var theirPair = cipherStream(theirPrivate, yourPublic, true);
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

takes 3 arguments, your private key, the person on the other end's public key,
and a boolean that you should set to true if you are receiving the message.

# under no circumstances should this be used for real life things that need to be kept secret

seriously it's for a demo.
