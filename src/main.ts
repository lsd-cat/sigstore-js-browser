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
import { bufferEqual, hash, createPublicKey } from './core/crypto';

import * as encoding from './core/encoding';

const testData = [
    // Example w/ padding
    {
      decoded: 'hello world',
      encoded: 'aGVsbG8gd29ybGQ=',
      urlEncoded: 'aGVsbG8gd29ybGQ',
    },
    // Example w/o padding
    {
      decoded: 'abstractiveness',
      encoded: 'YWJzdHJhY3RpdmVuZXNz',
      urlEncoded: 'YWJzdHJhY3RpdmVuZXNz',
    },
    // Example with URL-unsafe chars
    {
      decoded: 'a??~}~z',
      encoded: 'YT8/fn1+eg==',
      urlEncoded: 'YT8_fn1-eg',
    },
  ];
  
  
  testData.forEach((entry) => {
    console.log(encoding.base64Encode(entry.decoded) == entry.encoded)
  });
    
  testData.forEach((entry) => {
    console.log(encoding.base64Decode(entry.encoded) == entry.decoded);
  });
  

const digest = await hash('hello world');
console.log(encoding.uint8ArrayToHex(digest) == 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9')

const a = encoding.stringToUint8Array('hello world');
const b = encoding.stringToUint8Array('hello world');
console.log(bufferEqual(a, b) == true);

const c = encoding.stringToUint8Array('hello world');
const d = encoding.stringToUint8Array('hello world!');
console.log(bufferEqual(c, d) == false)

const input1 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFw
rkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----`;
const key = await createPublicKey(input1);
console.log(key.algorithm.name == "ECDSA");

const input2 = encoding.base64ToUint8Array(
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw=='
    );
const key2 = await createPublicKey(input2);
console.log(key2.algorithm.name == "ECDSA");
//expect(key).toBeDefined();
//expect(key.asymmetricKeyType).toBe('ec');
//expect(key.asymmetricKeyDetails).toEqual({ namedCurve: 'prime256v1' });