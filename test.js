'use strict';
var dhStream = require('./');
var test = require('tape');
var Transform = require('readable-stream').Transform;
var randomBytes = require('randombytes');
var createECDH = require('create-ecdh');
var createECDHBrowser = require('create-ecdh/browser');

function getECDH(type) {
  try {
    return createECDH(type);
  } catch (e) {
    return createECDHBrowser(type);
  }
}
function run(type, length, chunks) {
  test(type + ' run with ' + chunks + ' chunks of length ' + length, function (t) {
    var inData = [];
    var interData1 = [];
    var outData1 = [];
    var interData2 = [];
    var outData2 = [];
    var done = 0;
    var pair1 = dhStream(type);
    var pair2 = dhStream(type);
    pair1.secret.pipe(new Transform({
      transform: function (chunk, _, next) {
        interData1.push(chunk.toString('base64'));
        this.push(chunk);
        next();
      }
    })).pipe(pair2.secret);
    pair2.secret.pipe(new Transform({
      transform: function (chunk, _, next) {
        interData2.push(chunk.toString('base64'));
        this.push(chunk);
        next();
      }
    })).pipe(pair1.secret);
    var i = 0;
    function pushChunk(done) {
      var chunk = randomBytes(length);
      inData.push(chunk.toString('base64'));
      pair1.plain.write(chunk, function (err) {
        i++;
        t.error(err, 'no error on write ' + i + ' pair 1');
        pair2.plain.write(chunk, function (err) {
          t.error(err, 'no error on write ' + i + ' pair 2');
          if ((done + 1) === chunks) {
            pair1.plain.end();
            pair2.plain.end();
          } else {
            pushChunk(done + 1);
          }
        });
      });
    }
    function maybeEnd() {
      done++;
      if (done < 2) {
        return;
      }
      var inStr = inData.join('');
      var outStr1 = outData1.join('');
      var interStr1 = interData1.join('');
      var outStr2 = outData2.join('');
      var interStr2 = interData2.join('');
      t.equal(inStr, outStr1, 'strings are equals');
      t.notEqual(inStr, interStr1, 'encrypted is not the same as input');
      t.notEqual(outStr1, interStr1, 'encrypted is not the same as output');
      t.equal(inStr, outStr2, 'strings are equals');
      t.notEqual(inStr, interStr2, 'encrypted is not the same as input');
      t.notEqual(outStr2, interStr2, 'encrypted is not the same as output');
      t.notEqual(interStr1, interStr2, 'inter strings are not equal');
      t.equal(outStr1, outStr2, 'out strings are equal');
      t.end();
    }
    pushChunk(0);
    pair1.plain.on('data', function (d) {
      outData1.push(d.toString('base64'));
    }).on('end', maybeEnd);
    pair2.plain.on('data', function (d) {
      outData2.push(d.toString('base64'));
    }).on('end', maybeEnd);
  });
  test('long term keys ' + type + ' run with ' + chunks + ' chunks of length ' + length, function (t) {
    var set1 = getECDH(type);
    set1.generateKeys();
    var set2 = getECDH(type);
    set2.generateKeys();
    var inData = [];
    var interData1 = [];
    var outData1 = [];
    var interData2 = [];
    var outData2 = [];
    var done = 0;
    var pair1 = dhStream(type, set1.getPrivateKey(), set2.getPublicKey());
    var pair2 = dhStream(type, set2.getPrivateKey(), set1.getPublicKey());
    pair1.secret.pipe(new Transform({
      transform: function (chunk, _, next) {
        interData1.push(chunk.toString('base64'));
        this.push(chunk);
        next();
      }
    })).pipe(pair2.secret);
    pair2.secret.pipe(new Transform({
      transform: function (chunk, _, next) {
        interData2.push(chunk.toString('base64'));
        this.push(chunk);
        next();
      }
    })).pipe(pair1.secret);
    var i = 0;
    function pushChunk(done) {
      var chunk = randomBytes(length);
      inData.push(chunk.toString('base64'));
      pair1.plain.write(chunk, function (err) {
        i++;
        t.error(err, 'no error on write ' + i + ' pair 1');
        pair2.plain.write(chunk, function (err) {
          t.error(err, 'no error on write ' + i + ' pair 2');
          if ((done + 1) === chunks) {
            pair1.plain.end();
            pair2.plain.end();
          } else {
            pushChunk(done + 1);
          }
        });
      });
    }
    function maybeEnd() {
      done++;
      if (done < 2) {
        return;
      }
      var inStr = inData.join('');
      var outStr1 = outData1.join('');
      var interStr1 = interData1.join('');
      var outStr2 = outData2.join('');
      var interStr2 = interData2.join('');
      t.equal(inStr, outStr1, 'strings are equals');
      t.notEqual(inStr, interStr1, 'encrypted is not the same as input');
      t.notEqual(outStr1, interStr1, 'encrypted is not the same as output');
      t.equal(inStr, outStr2, 'strings are equals');
      t.notEqual(inStr, interStr2, 'encrypted is not the same as input');
      t.notEqual(outStr2, interStr2, 'encrypted is not the same as output');
      t.notEqual(interStr1, interStr2, 'inter strings are not equal');
      t.equal(outStr1, outStr2, 'out strings are equal');
      t.end();
    }
    pushChunk(0);
    pair1.plain.on('data', function (d) {
      outData1.push(d.toString('base64'));
    }).on('end', maybeEnd);
    pair2.plain.on('data', function (d) {
      outData2.push(d.toString('base64'));
    }).on('end', maybeEnd);
  });
}
var lengths = [1, 8, 12, 64, 128, 512, 639, 777, 1024, 2048];
var types = [ 'secp256k1',
  'secp224r1',
  'prime256v1',
  'prime192v1',
  'ed25519',
  'curve25519' ];

types.forEach(function (type) {
  lengths.forEach(function (length) {
    var i = 0;
    while (++i <= 4) {
      run(type, length, i * 4);
    }
  });
});
