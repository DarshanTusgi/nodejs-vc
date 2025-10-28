import { test } from 'node:test';
import assert from 'assert';
import crypto from 'crypto';
import { VerifiableCredentialService } from '../src/crypto/index.js';
import { VCBuilder } from '../src/builder/index.js';
import { JSONLDCanon } from '../src/crypto/index.js';

test('VerifiableCredentialService - sign and verify', () => {
  // Create the service
  const service = new VerifiableCredentialService();
  
  // Generate EC key pair for testing
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });
  
  // Create a sample verifiable credential using VCBuilder
  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addContext('https://www.w3.org/2018/credentials/examples/v1')
    .addType('VerifiableCredential')
    .addType('UniversityDegreeCredential')
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
  
  // Sign the VC
  const signedVc = service.sign(vc, privateKey);
  
  // Verify that the proof was added
  assert.ok(signedVc.proof);
  assert.ok(signedVc.proof.proofValue); // Changed from jws to proofValue
  assert.ok(signedVc.proof.created);
  
  // Verify the signed VC
  const isValid = service.verify(signedVc, publicKey);
  assert.strictEqual(isValid, true, 'The signed VC should be valid');
});

test('VerifiableCredentialService - verify with invalid signature', () => {
  // Create the service
  const service = new VerifiableCredentialService();
  
  // Generate EC key pair for testing
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });
  
  // Create a sample verifiable credential
  const vc = new VCBuilder()
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
  
  // Sign the VC
  const signedVc = service.sign(vc, privateKey);
  
  // Tamper with the signature
  const originalProofValue = signedVc.proof.proofValue; // Changed from jws to proofValue
  // Modify the signature
  signedVc.proof.proofValue = originalProofValue.substring(0, originalProofValue.length - 5) + 'XXXXX'; // Changed from jws to proofValue
  
  // Verify the tampered VC - should fail
  const isValid = service.verify(signedVc, publicKey);
  assert.strictEqual(isValid, false, 'The tampered VC should be invalid');
});

test('VerifiableCredentialService - verify without proof', () => {
  // Create the service
  const service = new VerifiableCredentialService();
  
  // Generate EC key pair for testing
  const { publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });
  
  // Create a sample verifiable credential without proof
  const vc = new VCBuilder()
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
  
  // Verify the VC without proof - should fail
  const isValid = service.verify(vc, publicKey);
  assert.strictEqual(isValid, false, 'VC without proof should be invalid');
});

test('JSONLDCanon helper', () => {
  // Create a sample verifiable credential
  const vc = new VCBuilder()
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
  
  // Test canonicalization
  const canonicalVc = JSONLDCanon.canonicalize(vc);
  assert.ok(canonicalVc);
  assert.ok(typeof canonicalVc === 'string');
  assert.ok(canonicalVc.length > 0);
});

test('VerifiableCredentialService - Base64 key support', () => {
  // Create the service
  const service = new VerifiableCredentialService();
  
  // Generate a wallet with Base64 keys
  const wallet = VerifiableCredentialService.createWallet();
  
  // Create a sample verifiable credential
  const vc = new VCBuilder()
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
  
  // Sign with Base64 private key
  const signedVc = service.sign(vc, wallet.privateKey);
  
  // Verify that the proof was added
  assert.ok(signedVc.proof);
  assert.ok(signedVc.proof.proofValue); // Changed from jws to proofValue
  
  // Verify with Base64 public key
  const isValid = service.verify(signedVc, wallet.publicKey);
  assert.strictEqual(isValid, true, 'The signed VC should be valid with Base64 keys');
});

test('VerifiableCredentialService - generateKeyPair helper', () => {
  // Generate key pair
  const keyPair = VerifiableCredentialService.generateKeyPair();
  
  // Check that both keys exist
  assert.ok(keyPair.publicKey);
  assert.ok(keyPair.privateKey);
  assert.ok(typeof keyPair.publicKey === 'string');
  assert.ok(typeof keyPair.privateKey === 'string');
  
  // Create service and test with generated keys
  const service = new VerifiableCredentialService();
  
  // Create a sample verifiable credential
  const vc = new VCBuilder()
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
  
  // Sign and verify with generated keys
  const signedVc = service.sign(vc, keyPair.privateKey);
  const isValid = service.verify(signedVc, keyPair.publicKey);
  assert.strictEqual(isValid, true, 'Should work with generated Base64 keys');
});