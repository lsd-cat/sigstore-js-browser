/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { bufferEqual, createPublicKey, hash } from '../crypto';
import { base64ToUint8Array, stringToUint8Array, uint8ArrayToHex } from '../encoding';

describe('createPublicKey', () => {
  it('should create a public key from a PEM string', () => {
    const input = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFw
rkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----`;
    createPublicKey(input).then(key => {
      expect(key).toBeDefined();
      expect(key.algorithm.name).toEqual('ECDSA');
    })
  });

  it('should create a public key from a DER buffer', () => {
    const input = base64ToUint8Array(
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw=='
    );
    const key = createPublicKey(input);
    createPublicKey(input).then(key => {
      expect(key).toBeDefined();
      expect(key.algorithm.name).toEqual('ECDSA');
    })
  });
});

describe('hash', () => {
  it('returns the SHA256 digest of the blob', () => {
    const blob = stringToUint8Array('hello world');
    hash(blob).then(digest => {
      expect(uint8ArrayToHex(digest)).toBe(
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      );
    })
  });
});

describe('bufferEqual', () => {
  it('returns true when the buffers are equal', () => {
    const a = stringToUint8Array('hello world');
    const b = stringToUint8Array('hello world');
    expect(bufferEqual(a, b)).toBe(true);
  });

  it('returns false when the buffers are not equal', () => {
    const a = stringToUint8Array('hello world');
    const b = stringToUint8Array('hello world!');
    expect(bufferEqual(a, b)).toBe(false);
  });
});
