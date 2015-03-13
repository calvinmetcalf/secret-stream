'use strict';
var createECDH = require('create-ecdh');
var sign = require('browserify-sign');
var stream = require('readable-stream');
var inherits = require('inherits');
var randomBytes = require('randombytes');
var createHmac = require('create-hmac');
var aes = require('browserify-aes');
var hmacStream = require('hmac-stream');
var duplexify = require('duplexify');
var ZEROBUF = new Buffer(32);
ZEROBUF.fill(0);
module.exports = cipherStream;
function cipherStream(privateKey, publicKey, reciever){
  var dh = createECDH('secp256k1');
  var dhPublic = dh.generateKeys();

  var random = randomBytes(16);
  var decrypter = new Decrypter(publicKey);
  var encryptedOut = new stream.PassThrough();
  var len = new Buffer([16, dhPublic.length]);
  var sig = sign.createSign('RSA-SHA256').update(len).update(random).update(dhPublic).sign(privateKey);
  var sigLen = new Buffer(2);
  sigLen.writeUInt16BE(sig.length, 0);
  encryptedOut.write(sigLen);
  encryptedOut.write(sig);
  encryptedOut.write(len);
  encryptedOut.write(random);
  encryptedOut.write(dhPublic);
  var plainOut = duplexify();
  var cipherOut = duplexify(decrypter, encryptedOut);
  decrypter.on('reply', function (data) {
    var secret = dh.computeSecret(data.dh);
    var otherRandom = data.random;
    var combinedRandom = reciever ? Buffer.concat([random, otherRandom]) : Buffer.concat([otherRandom, random]);
    var key = createHmac('sha256', combinedRandom).update(secret).digest();
    var iv1 = new Buffer(16);
    iv1.fill(0);
    var iv2 = new Buffer(16);
    iv2.fill(0);
    iv2[0] = 0x80;
    var encryptIv, decryptIv;
    if (reciever) {
      encryptIv = iv1;
      decryptIv = iv2;
    } else {
      encryptIv = iv2;
      decryptIv = iv1;
    }
    var cipher = aes.createCipheriv('aes-256-ctr', key, encryptIv);
    var authStream = new hmacStream.Authenticate(cipher.update(ZEROBUF));
    cipher.pipe(authStream).pipe(encryptedOut);
    plainOut.setWritable(cipher);
    var decipher = aes.createCipheriv('aes-256-ctr', key, decryptIv);
    var verifyStream = new hmacStream.Verify(decipher.update(ZEROBUF));
    decrypter.pipe(verifyStream).pipe(decipher);
    verifyStream.on('error', function (e) {
      decipher.emit('error', e);
    });
    plainOut.setReadable(decipher);
  });
  return {
    plain: plainOut,
    secret: cipherOut
  };
}

inherits(Decrypter, stream.Transform);
function Decrypter(publicKey) {
  stream.Transform.call(this);
  this.publicKey = publicKey;
  this.waitingToStart = true;
  this.cache = new Buffer('');
  this.cipher = null;
  this.sig = null;
  this.sigLen = null;
  this.random = null;
  this.randDhLength = null;
  this.randLenth = null;
  this.dhLength = null;
  this.dh = null;

}
Decrypter.prototype._transform = function (chunk, _, next) {
  var self = this;
  if (this.waitingToStart) {
    this.cache = Buffer.concat([this.cache, chunk]);
    if (this.sigLen === null) {
      if (this.cache.length < 2) {
        return next();
      }
      this.sigLen = this.cache.readUInt16BE(0);
      this.cache = this.cache.slice(2);
    }
    if (this.sig === null) {
      if (this.cache.length < this.sigLen) {
        return next();
      }
      this.sig = this.cache.slice(0, this.sigLen);
      this.cache = this.cache.slice(this.sigLen);
    }
    if (this.randDhLength === null) {
      if (this.cache.length < 2) {
        return next();
      }
      this.randDhLength = this.cache.slice(0, 2);
      this.cache = this.cache.slice(2);
      this.randLength = this.randDhLength[0];
      this.dhLength = this.randDhLength[1];
    }
    if (this.random === null) {
      if (this.cache.length < this.randLenth) {
        return next();
      }
      this.random = this.cache.slice(0, this.randLength);
      this.cache = this.cache.slice(this.randLength);
    }
    if (this.dh === null) {
      if (this.cache.length < this.dhLength) {
        return next();
      }
      this.dh = this.cache.slice(0, this.dhLength);
      this.cache = this.cache.slice(this.dhLength);
      var verified = sign.createVerify('RSA-SHA256').update(this.randDhLength)
        .update(this.random).update(this.dh).verify(this.publicKey, this.sig);
      if (verified) {
        this.emit('reply', {
          dh: this.dh,
          random: this.random
        });
        this.waitingToStart = false;
        if (this.cache.length) {
          this.push(this.cache);
        }
        self.publicKey = null;
        self.cache = null;
        self.sig = null;
        self.sigLen = null;
        self.random = null;
        self.randDhLength = null;
        self.randLenth = null;
        self.dhLength = null;
        self.dh = null;
        return next();
      } else {
        this.emit('error', new Error('unable to verify'));
        return next();
      }
    }
  }
  this.push(chunk);
  next();
};
/*

plain writable -> encrypted readable
encrypted writable -> plain readable
*/
