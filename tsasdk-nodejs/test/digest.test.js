'use strict';

const assert = require('assert');
const { computeHash, DigestAlgorithm, DIGEST_OID } = require('../src');

assert.strictEqual(
  computeHash('abc', DigestAlgorithm.SHA256).toString('hex'),
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
);

assert.strictEqual(
  computeHash('abc', DigestAlgorithm.SM3).toString('hex'),
  '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
);

assert.strictEqual(DIGEST_OID[DigestAlgorithm.SM3], '1.2.156.10197.1.401');
