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
import {
  parseBitString,
  parseBoolean,
  parseInteger,
  parseOID,
  parseStringASCII,
  parseTime,
} from '../../asn1/parse';
import { hexToUint8Array, stringToUint8Array } from '../../encoding';

describe('parseInteger', () => {
  it('parses positive integers', () => {
    expect(parseInteger(new Uint8Array([0x00]))).toEqual(BigInt(0));
    expect(parseInteger(new Uint8Array([0x7f]))).toEqual(BigInt(127));
    expect(parseInteger(new Uint8Array([0x00, 0x80]))).toEqual(BigInt(128));
    expect(parseInteger(new Uint8Array([0x01, 0x00]))).toEqual(BigInt(256));
  });

  it('parses negative integers', () => {
    expect(parseInteger(new Uint8Array([0xff]))).toEqual(BigInt(-1));
    expect(parseInteger(new Uint8Array([0x80]))).toEqual(BigInt(-128));
    expect(parseInteger(new Uint8Array([0xff, 0x7f]))).toEqual(BigInt(-129));
    expect(parseInteger(new Uint8Array([0xff, 0x00]))).toEqual(BigInt(-256));
  });
});

describe('parseStringASCII', () => {
  it('parses ASCII strings', () => {
    expect(parseStringASCII(new Uint8Array([0x48, 0x69, 0x21]))).toEqual('Hi!');
  });
});

describe('parseTime', () => {
  describe('with short year', () => {
    describe('when year is 50 or greater', () => {
      it('parses the date', () => {
        expect(parseTime(stringToUint8Array('740212121110Z'), true)).toEqual(
          new Date('1974-02-12T12:11:10Z')
        );
      });
    });

    describe('when year is less than 50', () => {
      it('parses the date', () => {
        expect(parseTime(stringToUint8Array('180212121110.099Z'), true)).toEqual(
          new Date('2018-02-12T12:11:10Z')
        );
      });
    });
  });

  describe('with long year', () => {
    it('parses the date', () => {
      expect(parseTime(stringToUint8Array('19180212121110Z'), false)).toEqual(
        new Date('1918-02-12T12:11:10Z')
      );
    });
  });

  describe('with long year and milliseconds', () => {
    it('parses the date', () => {
      expect(parseTime(stringToUint8Array('19180212121110.099Z'), false)).toEqual(
        new Date('1918-02-12T12:11:10Z')
      );
    });
  });

  describe('when the time is invalid', () => {
    it('throws an error', () => {
      expect(() => parseTime(stringToUint8Array('FOOBAR'), true)).toThrow(
        'invalid time'
      );
    });
  });
});

describe('parseOID', () => {
  const tests = [
    {
      oid: '2A8648CE3D040303',
      expected: '1.2.840.10045.4.3.3',
    },
    {
      oid: '2b0601040182371514',
      expected: '1.3.6.1.4.1.311.21.20',
    },
    {
      oid: '2a8648ce3d0201',
      expected: '1.2.840.10045.2.1',
    },
    {
      oid: '2b0601040183bf300103',
      expected: '1.3.6.1.4.1.57264.1.3',
    },
    {
      oid: '2B06010401D679020402',
      expected: '1.3.6.1.4.1.11129.2.4.2',
    },
    {
      oid: '5381ab2501',
      expected: '2.3.21925.1',
    },
  ];

  it('parses OID strings', () => {
    tests.forEach(({ oid, expected }) => {
      expect(parseOID(hexToUint8Array(oid))).toEqual(expected);
    });
  });
});

describe('parseBoolean', () => {
  it('parses boolean values', () => {
    expect(parseBoolean(new Uint8Array([0x00]))).toEqual(false);
    expect(parseBoolean(new Uint8Array([0xff]))).toEqual(true);
  });
});

describe('parseBitString', () => {
  it('parses bit strings', () => {
    expect(parseBitString(new Uint8Array([0x04, 0x57, 0xd0]))).toEqual([
      0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1,
    ]);

    // Since the last four bits are ignored, the parsed bit string is
    // identical to the example above.
    expect(parseBitString(new Uint8Array([0x04, 0x57, 0xdf]))).toEqual([
      0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1,
    ]);
  });
});
