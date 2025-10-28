import { test } from 'node:test';
import assert from 'assert';
import { VCBuilder } from '../src/builder/index.js';
import { JSONLDCanon } from '../src/crypto/index.js';

/**
 * Test suite to validate deterministic JSON-LD canonicalization
 * This is critical for ensuring consistent serialization for cryptographic operations
 */

test('DETERMINISTIC: JSON-LD Canonicalization produces consistent output', () => {
  // Create identical VCs using different construction orders
  const vc1 = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/1872')
    .issuer('https://example.edu/issuers/565049')
    .issuanceDate('2010-01-01T19:23:24Z')
    .credentialSubject({
      id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
      degree: {
        type: 'BachelorDegree',
        name: 'Bachelor of Science and Arts'
      }
    })
    .build();

  // Create the same VC with different property order
  const vc2 = new VCBuilder()
    .id('http://example.edu/credentials/1872')
    .issuer('https://example.edu/issuers/565049')
    .addType('VerifiableCredential')
    .issuanceDate('2010-01-01T19:23:24Z')
    .addContext('https://www.w3.org/2018/credentials/v1')
    .credentialSubject({
      degree: {
        name: 'Bachelor of Science and Arts',
        type: 'BachelorDegree'
      },
      id: 'did:example:ebfeb1f712ebc6f1c276e12ec21'
    })
    .build();

  // Canonicalize both VCs
  const canonical1 = JSONLDCanon.canonicalize(vc1);
  const canonical2 = JSONLDCanon.canonicalize(vc2);

  // They should produce identical canonicalized output
  assert.strictEqual(canonical1, canonical2, 'Canonicalization should be deterministic regardless of property order');
});

test('CANONICALIZATION: Proof exclusion parameter', () => {
  // Create VC with proof field
  const vcWithProof = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/12345')
    .issuer('https://example.edu/issuers/56789')
    .issuanceDate('2020-01-01T12:00:00Z')
    .credentialSubject({
      id: 'did:example:abcdef123456',
      achievement: 'Completed Advanced Course'
    })
    .build();

  // Add a proof to the VC
  vcWithProof.proof = {
    type: 'EcdsaSecp256r1Signature2019',
    created: '2020-01-01T12:01:00Z',
    verificationMethod: 'did:example:123#key-1',
    proofPurpose: 'assertionMethod',
    proofValue: 'signatureValue'
  };

  // Create the same VC without proof
  const vcWithoutProof = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/12345')
    .issuer('https://example.edu/issuers/56789')
    .issuanceDate('2020-01-01T12:00:00Z')
    .credentialSubject({
      id: 'did:example:abcdef123456',
      achievement: 'Completed Advanced Course'
    })
    .build();

  // Canonicalize with proof exclusion - should produce identical output to VC without proof
  const canonicalWithExclusion = JSONLDCanon.canonicalize(vcWithProof, true);
  const canonicalWithoutProof = JSONLDCanon.canonicalize(vcWithoutProof);

  // They should produce identical canonicalized output (proof is excluded)
  assert.strictEqual(
    canonicalWithExclusion, 
    canonicalWithoutProof, 
    'Canonicalization with proof exclusion should match VC without proof'
  );
  
  // Canonicalization without exclusion should include proof
  const canonicalWithoutExclusion = JSONLDCanon.canonicalize(vcWithProof, false);
  assert.notStrictEqual(
    canonicalWithoutExclusion,
    canonicalWithoutProof,
    'Canonicalization without proof exclusion should include proof'
  );
});