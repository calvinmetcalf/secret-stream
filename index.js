'use strict';
var duplexify = require('duplexify');
var PassThrough = require('readable-stream').PassThrough;
var createECDH = require('create-ecdh');
var createECDHBrowser = require('create-ecdh/browser');
var cryptoStream = require('crypto-stream');
var randomBytes = require('randombytes');
var createHmac = require('create-hmac');
var kdf = require('pbkdf2');
var HeaderStream = require('headerstream');
var keyLens = {
  secp256k1: 33,
  secp224r1: 29,
  prime256v1: 33,
  prime192v1: 25,
  ed25519: 33,
  curve25519: 32
};
keyLens.p224 = keyLens.secp224r1;
keyLens.p256 = keyLens.secp256r1 = keyLens.prime256v1;
keyLens.p192 = keyLens.secp192r1 = keyLens.prime192v1;
var ITERATIONS = 500; // mainly just to smooth out the size

function getECDH(type) {
  try {
    return createECDH(type);
  } catch (e) {
    return createECDHBrowser(type);
  }
}
/*

plain writable -> encrypted readable
encrypted writable -> plain readable
*/
function passfn(a){
  return a;
}
function makeEmbelishKey(type, yourPrivate, theirPublic, dh, otherPublic) {
  return embelishKey;
  function embelishKey(key, decrypt) {
    var hmac = createHmac('sha256', key);
    var piece1 = dh.computeSecret(theirPublic);
    var dh2 = getECDH(type);
    dh2.generateKeys();
    dh2.setPrivateKey(yourPrivate);
    var piece2 = dh2.computeSecret(otherPublic);
    if (decrypt) {
      hmac.update(piece1).update(piece2);
    } else {
      hmac.update(piece2).update(piece1);
    }
    return hmac.digest();
  }
}
function createDHpair(type, yourPrivate, theirPublic) {
  var encrypter = duplexify();
  var decrypter = duplexify();
  var encrypterOut = new PassThrough();
  encrypter.setReadable(encrypterOut);
  type = type || 'secp256k1';
  if (!keyLens[type]) {
    throw new Error('unknown curve');
  }
  var dh = getECDH(type);
  var publicKey = dh.generateKeys(null, 'compressed');
  var salt = randomBytes(16);
  encrypterOut.write(publicKey);
  encrypterOut.write(salt);
  var decrypterIn = new HeaderStream((keyLens[type] + 16), function (err, resp) {
    if (err) {
      decrypter.emit('error', err);
      return encrypter.emit('error', err);
    }
    var otherPublicKey = resp.slice(0, -16);
    var otherSalt = resp.slice(-16);
    var encryptSalt = otherSalt + salt;
    var decryptSalt = salt + otherSalt;
    var derivedSecret = dh.computeSecret(otherPublicKey);
    var embelishKey;
    if (!yourPrivate || !theirPublic) {
      embelishKey = passfn;
    } else {
      embelishKey = makeEmbelishKey(type, yourPrivate, theirPublic, dh, otherPublicKey);
    }
    kdf.pbkdf2(derivedSecret, encryptSalt, ITERATIONS, 32, 'sha256', function (err, resp) {
      if (err) {
        return encrypter.emit('error', err);
      }
      var crypto = cryptoStream.encrypt(embelishKey(resp));
      crypto.pipe(encrypterOut);
      encrypter.setWritable(crypto);
    });
    kdf.pbkdf2(derivedSecret, decryptSalt, ITERATIONS, 32, 'sha256', function (err, resp) {
      if (err) {
        return decrypter.emit('error', err);
      }
      var crypto = cryptoStream.decrypt(embelishKey(resp, true));
      decrypterIn.pipe(crypto);
      decrypter.setReadable(crypto);
    });
  });
  decrypter.setWritable(decrypterIn);
  return {
    secret: duplexify(decrypter, encrypter),
    plain: duplexify(encrypter, decrypter)
  };
}
module.exports = createDHpair;
