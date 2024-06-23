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
import { ASN1Obj } from '../../asn1';
import {
  X509AuthorityKeyIDExtension,
  X509BasicConstraintsExtension,
  X509Extension,
  X509KeyUsageExtension,
  X509SCTExtension,
  X509SubjectAlternativeNameExtension,
  X509SubjectKeyIDExtension,
} from '../../x509/ext';
import { SignedCertificateTimestamp } from '../../x509/sct';
import { hexToUint8Array, uint8ArrayToHex } from '../../encoding';

describe('x509Extension', () => {
  describe('constructor', () => {
    const extension = hexToUint8Array('300F0603551D130101FF040530030101FF');
    const obj = ASN1Obj.parseBuffer(extension);

    it('parses the extension', () => {
      const subject = new X509Extension(obj);
      expect(subject.critical).toBe(true);
      expect(subject.oid).toBe('2.5.29.19');
    });
  });

  describe('#value', () => {
    const extension = hexToUint8Array('300F0603551D130101FF040530030101FF');
    const subject = new X509Extension(ASN1Obj.parseBuffer(extension));

    it('returns the value', () => {
      expect(uint8ArrayToHex(subject.value)).toBe('30030101ff');
    });
  });

  describe('#valueObj', () => {
    const extension = hexToUint8Array('300F0603551D130101FF040530030101FF');
    const subject = new X509Extension(ASN1Obj.parseBuffer(extension));

    it('returns the value', () => {
      const obj = subject.valueObj;
      expect(obj.tag.number).toBe(0x04);
      expect(obj.subs.length).toBe(1);
    });
  });
});

describe('x509BasicConstraintsExtension', () => {
  describe('constructor', () => {
    const basicConstraintsExtension = hexToUint8Array(
      '300F0603551D130101FF040530030101FF'
    );
    const obj = ASN1Obj.parseBuffer(basicConstraintsExtension);

    it('parses the extension', () => {
      const subject = new X509BasicConstraintsExtension(obj);
      expect(subject.critical).toBe(true);
      expect(subject.oid).toBe('2.5.29.19');
    });
  });

  describe('#isCA', () => {
    describe('when the extension is not a CA', () => {
      // Extension w/ isCA = false
      const basicConstraintsExtension = hexToUint8Array(
        '300F0603551D130101FF04053003010100'
      );
      const subject = new X509BasicConstraintsExtension(
        ASN1Obj.parseBuffer(basicConstraintsExtension)
      );

      it('returns false', () => {
        expect(subject.isCA).toBe(false);
      });
    });

    describe('when the extension is a CA', () => {
      // Extension w/ isCA = true
      const basicConstraintsExtension = hexToUint8Array(
        '300F0603551D130101FF040530030101FF'
      );
      const subject = new X509BasicConstraintsExtension(
        ASN1Obj.parseBuffer(basicConstraintsExtension)
      );

      it('returns true', () => {
        expect(subject.isCA).toBe(true);
      });
    });

    describe('when the extension contains no value for the CA', () => {
      // Extension w/ NO isCA value specified
      const basicConstraintsExtension = hexToUint8Array(
        '300C0603551D130101FF04023000'

      );
      const subject = new X509BasicConstraintsExtension(
        ASN1Obj.parseBuffer(basicConstraintsExtension)
      );

      it('returns false', () => {
        expect(subject.isCA).toBe(false);
      });
    });
  });

  describe('#pathLenConstraint', () => {
    describe('when the extension has no pathLenConstraint', () => {
      // Extension w/ isCA = true, no pathLenConstraint
      const basicConstraintsExtension = hexToUint8Array(
        '300F0603551D130101FF040530030101FF'
      );
      const subject = new X509BasicConstraintsExtension(
        ASN1Obj.parseBuffer(basicConstraintsExtension)
      );

      it('returns undefined', () => {
        expect(subject.pathLenConstraint).toBeUndefined();
      });
    });

    describe('when the extension has a pathLenConstraint', () => {
      // Extension w/ isCA = true, no pathLenConstraint
      const basicConstraintsExtension = hexToUint8Array(
        '30120603551D130101FF040830060101FF020101'
      );
      const subject = new X509BasicConstraintsExtension(
        ASN1Obj.parseBuffer(basicConstraintsExtension)
      );

      it('returns the pathLen', () => {
        expect(subject.pathLenConstraint).toEqual(1n);
      });
    });
  });
});

describe('x509KeyUsageExtension', () => {
  describe('constructor', () => {
    const keyUsageExtension = hexToUint8Array(
      '300E0603551D0F0101FF040403020780'
    );
    const obj = ASN1Obj.parseBuffer(keyUsageExtension);

    it('parses the extension', () => {
      const subject = new X509KeyUsageExtension(obj);
      expect(subject.critical).toBe(true);
      expect(subject.oid).toBe('2.5.29.15');
    });
  });

  describe('#digitalSignature', () => {
    describe('when the extension has the digitalSignature bit set', () => {
      // Extension w/ digitalSignature bit set
      const keyUsageExtension = hexToUint8Array(
        '300E0603551D0F0101FF040403020780'
      );
      const subject = new X509KeyUsageExtension(
        ASN1Obj.parseBuffer(keyUsageExtension)
      );

      it('returns true', () => {
        expect(subject.digitalSignature).toBe(true);
      });
    });

    describe('when the extension does not have the digitalSignature bit set', () => {
      // Extension w/ digitalSignature bit unset
      const keyUsageExtension = hexToUint8Array(
        '300E0603551D0F0101FF040403020700'
      );
      const subject = new X509KeyUsageExtension(
        ASN1Obj.parseBuffer(keyUsageExtension)
      );

      it('returns false', () => {
        expect(subject.digitalSignature).toBe(false);
      });
    });
  });

  describe('#keyCertSign', () => {
    describe('when the extension has the keyCertSign bit set', () => {
      // Extension w/ keyCertSign bit set
      const keyUsageExtension = hexToUint8Array(
        '300E0603551D0F0101FF040403020204'
      );
      const subject = new X509KeyUsageExtension(
        ASN1Obj.parseBuffer(keyUsageExtension)
      );

      it('returns true', () => {
        expect(subject.keyCertSign).toBe(true);
      });
    });

    describe('when the extension does not have the keyCertSign bit set', () => {
      // Extension w/ keyCertSign bit unset
      const keyUsageExtension = hexToUint8Array(
        '300E0603551D0F0101FF040403020200'
      );
      const subject = new X509KeyUsageExtension(
        ASN1Obj.parseBuffer(keyUsageExtension)
      );

      it('returns false', () => {
        expect(subject.keyCertSign).toBe(false);
      });
    });
  });

  describe('#crlSign', () => {
    describe('when the extension has the cRLSign bit set', () => {
      // Extension w/ cRLSign bit set
      const keyUsageExtension = hexToUint8Array(
        '300E0603551D0F0101FF040403020102'
      );
      const subject = new X509KeyUsageExtension(
        ASN1Obj.parseBuffer(keyUsageExtension)
      );

      it('returns true', () => {
        expect(subject.crlSign).toBe(true);
      });
    });

    describe('when the extension does not have the cRLSign bit set', () => {
      // Extension w/ cRLSign bit unset
      const keyUsageExtension = hexToUint8Array(
        '300E0603551D0F0101FF040403020100'
      );
      const subject = new X509KeyUsageExtension(
        ASN1Obj.parseBuffer(keyUsageExtension)
      );

      it('returns false', () => {
        expect(subject.crlSign).toBe(false);
      });
    });
  });
});

describe('x509SubjectAlternativeNameExtension', () => {
  describe('constructor', () => {
    const subjectAltNameExtension = hexToUint8Array(
      '301F0603551D110101FF041530138111627269616E40646568616D65722E636F6D'
    );
    const obj = ASN1Obj.parseBuffer(subjectAltNameExtension);

    it('parses the extension', () => {
      const subject = new X509SubjectAlternativeNameExtension(obj);
      expect(subject.critical).toBe(true);
      expect(subject.oid).toBe('2.5.29.17');
    });
  });

  describe('#rfc822Name', () => {
    describe('when the extension has an rfc822Name', () => {
      // Extension w/ rfc822Name
      const subjectAltNameExtension = hexToUint8Array(
        '30190603551D110101FF040F300D810B666F6F406261722E636F6D'
      );
      const subject = new X509SubjectAlternativeNameExtension(
        ASN1Obj.parseBuffer(subjectAltNameExtension)
      );

      it('returns the rfc822Name', () => {
        expect(subject.rfc822Name).toBe('foo@bar.com');
      });
    });

    describe('when the extension has a uri', () => {
      // Extension w/ uri
      const subjectAltNameExtension = hexToUint8Array(
        '30190603551D110101FF040F300D860B666F6F406261722E636F6D'
      );
      const subject = new X509SubjectAlternativeNameExtension(
        ASN1Obj.parseBuffer(subjectAltNameExtension)
      );

      it('returns undefined', () => {
        expect(subject.rfc822Name).toBeUndefined();
      });
    });
  });

  describe('#uri', () => {
    describe('when the extension has a uri', () => {
      // Extension w/ uri
      const subjectAltNameExtension = hexToUint8Array(
        '30190603551D110101FF040F300D860B666F6F406261722E636F6D'
      );
      const subject = new X509SubjectAlternativeNameExtension(
        ASN1Obj.parseBuffer(subjectAltNameExtension)
      );

      it('returns the uri', () => {
        expect(subject.uri).toBe('foo@bar.com');
      });
    });

    describe('when the extension has an rfc822Name', () => {
      // Extension w/ rfc822Name
      const subjectAltNameExtension = hexToUint8Array(
        '30190603551D110101FF040F300D810B666F6F406261722E636F6D'
      );
      const subject = new X509SubjectAlternativeNameExtension(
        ASN1Obj.parseBuffer(subjectAltNameExtension)
      );

      it('returns undefined', () => {
        expect(subject.uri).toBeUndefined();
      });
    });
  });

  describe('#otherName', () => {
    describe('when the extension has an otherName', () => {
      // Extension w/ othername
      const subjectAltNameExtension = hexToUint8Array(
        '30260603551D11041F301DA01B060A2B0601040183BF300107A00D0C0B666F6F406261722E636F6D'
      );
      const subject = new X509SubjectAlternativeNameExtension(
        ASN1Obj.parseBuffer(subjectAltNameExtension)
      );

      it('returns the uri', () => {
        expect(subject.otherName('1.3.6.1.4.1.57264.1.7')).toBe('foo@bar.com');
      });
    });

    describe('when the incorrect otherName OID is specified', () => {
      // Extension w/ othername
      const subjectAltNameExtension = hexToUint8Array(
        '30260603551D11041F301DA01B060A2B0601040183BF300107A00D0C0B666F6F406261722E636F6D'
      );
      const subject = new X509SubjectAlternativeNameExtension(
        ASN1Obj.parseBuffer(subjectAltNameExtension)
      );

      it('returns the uri', () => {
        expect(subject.otherName('0.9.9')).toBeUndefined();
      });
    });

    describe('when the extension has an rfc822Name', () => {
      // Extension w/ rfc822Name
      const subjectAltNameExtension = hexToUint8Array(
        '30190603551D110101FF040F300D810B666F6F406261722E636F6D'
      );
      const subject = new X509SubjectAlternativeNameExtension(
        ASN1Obj.parseBuffer(subjectAltNameExtension)
      );

      it('returns the undefined', () => {
        expect(subject.otherName('1.3.6.1.4.1.57264.1.7')).toBeUndefined();
      });
    });
  });
});

describe('x509AuthorityKeyIDExtension', () => {
  describe('constructor', () => {
    const akiExtension = hexToUint8Array(
      '301F0603551D23041830168014875197D46B0D39CC9C44DFEDD1FBF77BF04F9B4F'
    );
    const obj = ASN1Obj.parseBuffer(akiExtension);

    it('parses the extension', () => {
      const subject = new X509AuthorityKeyIDExtension(obj);
      expect(subject.critical).toBe(false);
      expect(subject.oid).toBe('2.5.29.35');
    });
  });

  describe('#keyIdentifier', () => {
    describe('when the extension has a keyIdentifier', () => {
      // Extension w/ keyIdentifier
      const akiExtension = hexToUint8Array(
        '301F0603551D23041830168014875197D46B0D39CC9C44DFEDD1FBF77BF04F9B4F'
      );
      const subject = new X509AuthorityKeyIDExtension(
        ASN1Obj.parseBuffer(akiExtension)
      );

      it('returns the keyIdentifier', () => {
        expect(subject.keyIdentifier).toEqual(
          hexToUint8Array('875197D46B0D39CC9C44DFEDD1FBF77BF04F9B4F')
        );
      });
    });

    describe('when the extension has NO keyIdentifier', () => {
      // Extension w/o keyIdentifier (bad context-specific tag)
      const akiExtension = hexToUint8Array(
        '301F0603551D23041830168114875197D46B0D39CC9C44DFEDD1FBF77BF04F9B4F'
      );
      const subject = new X509AuthorityKeyIDExtension(
        ASN1Obj.parseBuffer(akiExtension)
      );

      it('returns the keyIdentifier', () => {
        expect(subject.keyIdentifier).toBeUndefined();
      });
    });
  });
});

describe('x509SubjectKeyIDExtension', () => {
  describe('constructor', () => {
    const skiExtension = hexToUint8Array(
      '301D0603551D0E04160414BC8EE9246141781B89DB3CAB61A94F825A34C5A8'
    );
    const obj = ASN1Obj.parseBuffer(skiExtension);

    it('parses the extension', () => {
      const subject = new X509SubjectKeyIDExtension(obj);
      expect(subject.critical).toBe(false);
      expect(subject.oid).toBe('2.5.29.14');
    });
  });

  describe('#keyIdentifier', () => {
    const skiExtension = hexToUint8Array(
      '301D0603551D0E04160414BC8EE9246141781B89DB3CAB61A94F825A34C5A8'
    );

    const subject = new X509SubjectKeyIDExtension(
      ASN1Obj.parseBuffer(skiExtension)
    );

    it('returns the keyIdentifier', () => {
      expect(subject.keyIdentifier).toEqual(
        hexToUint8Array('BC8EE9246141781B89DB3CAB61A94F825A34C5A8')
      );
    });
  });
});

describe('x509SCTExtension', () => {
  describe('constructor', () => {
    const sctExtension = hexToUint8Array(
      '3012060A2B06010401D679020402040404020000'
    );
    const obj = ASN1Obj.parseBuffer(sctExtension);

    it('parses the extension', () => {
      const subject = new X509SCTExtension(obj);
      expect(subject.critical).toBe(false);
      expect(subject.oid).toBe('1.3.6.1.4.1.11129.2.4.2');
    });
  });

  describe('#signedCertificateTimestamps', () => {
    describe('when there are no SCTs in the extension', () => {
      // Extension w/ zero-length array of SCTs
      const sctExtension = hexToUint8Array(
        '3012060A2B06010401D679020402040404020000'
      );
      const subject = new X509SCTExtension(ASN1Obj.parseBuffer(sctExtension));

      it('returns an empty array', () => {
        const scts = subject.signedCertificateTimestamps;
        expect(scts).toBeDefined();
        expect(scts).toHaveLength(0);
      });
    });

    describe('when there are SCTs in the extension', () => {
      const sctExtension = hexToUint8Array(
        '3043060A2B06010401D679020402043504330031002F0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      const subject = new X509SCTExtension(ASN1Obj.parseBuffer(sctExtension));

      it('returns an array of SCTs', () => {
        const scts = subject.signedCertificateTimestamps;
        expect(scts).toBeDefined();
        expect(scts).toHaveLength(1);
        expect(scts[0]).toBeInstanceOf(SignedCertificateTimestamp);
      });
    });

    describe('when the stated length of the SCT list does not match the data ', () => {
      // Extension where length of SCT list is mismatched with the length of the constituent SCTs
      const sctExtension = hexToUint8Array(
        //                                   |--| Should be 0x0031 for a valid SCT extension
        '3043060A2B06010401D67902040204350433002F002F0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      const subject = new X509SCTExtension(ASN1Obj.parseBuffer(sctExtension));

      it('throws an error', () => {
        expect(() => {
          subject.signedCertificateTimestamps;
        }).toThrow(/length does not match/);
      });
    });
  });
});
