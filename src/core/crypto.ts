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
import { stringToUint8Array } from './encoding';
import { toDER } from './pem';
import { ASN1Obj } from './asn1/obj';
import { ECDSA_CURVE_NAMES } from './oid';

type KeyLike = string | Uint8Array;
const SHA256_ALGORITHM = 'sha256';

class Hash {
  private algorithm: "SHA-256" | "SHA-384" | "SHA-512";
  private value: ArrayBuffer;

  constructor(algorithm: string) {
      if (algorithm.includes("512")) {
        this.algorithm = "SHA-512";
      } else if (algorithm.includes("384")) {
        this.algorithm = "SHA-384";
      } else {
        this.algorithm = "SHA-256";
      }
      this.value = new Uint8Array(0);
  }

  update(data: Uint8Array): void {
      if (typeof data === 'string') {
          data = stringToUint8Array(data);
      }

      var tmp = new Uint8Array(this.value.byteLength + data.byteLength);
      tmp.set(new Uint8Array(this.value), 0);
      tmp.set(new Uint8Array(data), this.value.byteLength);
      this.value = tmp;
  }

  async digest(): Promise<Uint8Array> {
    // This should fail if called multiple times; we con't care right now
    return new Uint8Array(await crypto.subtle.digest(this.algorithm, this.value));
  }
}

export async function createPublicKey(
  key: KeyLike,
  type: 'spki' | 'pkcs8' | 'raw' = 'spki'
): Promise<CryptoKey> {
  let options: EcKeyImportParams;
  let raw: Uint8Array;

  if (typeof key === "string") {
    raw = toDER(key);
  } else if (key instanceof Uint8Array) {
    raw = key;
  } else {
    throw new Error("Unsupported key format");
  }

  // We sadly have to find out the curve name manually
  options = {name: 'ECDSA', namedCurve: ECDSA_CURVE_NAMES[ASN1Obj.parseBuffer(raw).subs[0].subs[1].toOID()]};

  return await crypto.subtle.importKey(type, raw, options, true, ["verify"]);

}

function createHash(algorithm: string): Hash {
  return new Hash(algorithm);
}

export async function digest(algorithm: string, data: Uint8Array | string): Promise<Uint8Array> {
  const hash = createHash(algorithm);
  if (typeof data === "string") {
    hash.update(stringToUint8Array(data));
  } else {
    hash.update(data);
  }
  return hash.digest();
}

// TODO: deprecate this in favor of digest()
export async function hash(data: Uint8Array | string): Promise<Uint8Array> {
  const hash = createHash(SHA256_ALGORITHM);
  if (typeof data === "string") {
    hash.update(stringToUint8Array(data));
  } else {
    hash.update(data);
  }
  return hash.digest();
}

export async function verify(
  data: Uint8Array,
  key: CryptoKey,
  signature: Uint8Array,
  algorithm?: string
): Promise<boolean> {
  // The try/catch is to work around an issue in Node 14.x where verify throws
  // an error in some scenarios if the signature is invalid.
  let options: EcdsaParams;

  // Default to sha256
  let hash: 'SHA-256' | 'SHA-384' | 'SHA-512' = 'SHA-256';
  
  // Otherwise attempt another with this crappy heuristic
  if (algorithm && algorithm.includes("512")) {
    hash = "SHA-512";
  } else if (algorithm && algorithm.includes("384")) {
    hash = "SHA-384";
  }

  options = {name: 'ECDSA', hash: hash}
  crypto.subtle.verify(options, key, signature, data);
  return false;
}

// We can make this timesafe, but we are using it only to verify at this point :)
export function bufferEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

