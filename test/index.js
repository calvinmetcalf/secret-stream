var fs = require('fs');
var path = require('path');
var priv1 = fs.readFileSync(path.join(__dirname, '/fixtures/priv1.pem'));
var priv2 = fs.readFileSync(path.join(__dirname, '/fixtures/priv2.pem'));
var pub1 = fs.readFileSync(path.join(__dirname, '/fixtures/pub1.pem'));
var pub2 = fs.readFileSync(path.join(__dirname, '/fixtures/pub2.pem'));
var createCipher = require('../');
var test = require('tape');

test('thing1', function (t) {
  t.plan(2);
  var msg1 = 'hi from number 2';
  var msg2 = 'hi from number 1';
  var pair1 = createCipher(priv1, pub2);
  var pair2 = createCipher(priv2, pub1, true);
  pair1.secret.on('error', function (e){
    throw e;
  }).pipe(pair2.secret);
  pair2.secret.on('error', function (e){
    throw e;
  }).pipe(pair1.secret);
  pair1.plain.on('data', function (d){
    t.equals(d.toString(), msg1, msg1);
  });
  pair2.plain.on('data', function (d){
    t.equals(d.toString(), msg2, msg2);
  });
  pair1.plain.on('error', function (e){
    throw e;
  }).end(msg2);
  pair2.plain.on('error', function (e){
    throw e;
  }).end(msg1);
});
