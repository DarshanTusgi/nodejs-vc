import { test } from 'node:test';
import assert from 'assert';
import crypto from 'crypto';
import { VerifiableCredentialService } from '../src/crypto/index.js';
import { VCBuilder } from '../src/builder/index.js';
import { Proof } from '../src/core/index.js';

/**
 * Comprehensive test suite for Node.js Verifiable Credential implementation
 * Tests both positive and negative scenarios
 */

// Test data
const SAMPLE_VC = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential'],
  id: 'http://example.edu/credentials/1872',
  issuer: 'https://example.edu/issuers/565049',
  issuanceDate: '2010-01-01T19:23:24Z',
  credentialSubject: {
    id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    degree: {
      type: 'BachelorDegree',
      name: 'Bachelor of Science and Arts'
    }
  }
};

test('POSITIVE: Basic sign and verify flow', () => {
  const service = new VerifiableCredentialService();
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });

  // Create VC using builder
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
  
  // Validate proof structure
  assert.ok(signedVc.proof, 'Proof should be present');
  assert.strictEqual(signedVc.proof.type, 'EcdsaSecp256r1Signature2019', 'Proof type should be correct');
  assert.ok(signedVc.proof.created, 'Proof should have creation timestamp');
  assert.ok(signedVc.proof.verificationMethod, 'Proof should have verification method');
  assert.ok(signedVc.proof.proofPurpose, 'Proof should have purpose');
  assert.ok(signedVc.proof.proofValue, 'Proof should have proofValue');
  
  // Verify the signed VC
  const isValid = service.verify(signedVc, publicKey);
  assert.strictEqual(isValid, true, 'The signed VC should be valid');
});

test('POSITIVE: Base64 key support', () => {
  const service = new VerifiableCredentialService();
  const wallet = VerifiableCredentialService.createWallet();

  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/3456')
    .issuer('https://example.edu/issuers/12345')
    .issuanceDate('2020-01-01T10:00:00Z')
    .credentialSubject({
      id: 'did:example:abcdef123456',
      alumniOf: 'Example University'
    })
    .build();

  // Sign with Base64 private key
  const signedVc = service.sign(vc, wallet.privateKey);
  
  // Validate proof structure
  assert.ok(signedVc.proof, 'Proof should be present');
  assert.ok(signedVc.proof.proofValue, 'Proof should have proofValue');
  
  // Verify with Base64 public key
  const isValid = service.verify(signedVc, wallet.publicKey);
  assert.strictEqual(isValid, true, 'The signed VC should be valid with Base64 keys');
});

test('POSITIVE: Multiple proof handling', () => {
  const service = new VerifiableCredentialService();
  
  // Generate two key pairs
  const keyPair1 = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });
  
  const keyPair2 = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });

  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/7890')
    .issuer('https://example.edu/issuers/98765')
    .issuanceDate('2021-06-01T15:30:00Z')
    .credentialSubject({
      id: 'did:example:ghijkl789012',
      achievement: 'Completed Advanced Cryptography Course'
    })
    .build();

  // Sign with first key
  const signedVc1 = service.sign(vc, keyPair1.privateKey);
  assert.ok(signedVc1.proof.proofValue, 'First signature should be present');
  
  // Create a new VC with the same content and sign with second key
  const vc2 = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/7890')
    .issuer('https://example.edu/issuers/98765')
    .issuanceDate('2021-06-01T15:30:00Z')
    .credentialSubject({
      id: 'did:example:ghijkl789012',
      achievement: 'Completed Advanced Cryptography Course'
    })
    .build();
  
  const signedVc2 = service.sign(vc2, keyPair2.privateKey);
  assert.ok(signedVc2.proof.proofValue, 'Second signature should be present');
  
  // Both verifications should pass
  const isValid1 = service.verify(signedVc1, keyPair1.publicKey);
  const isValid2 = service.verify(signedVc2, keyPair2.publicKey);
  
  assert.strictEqual(isValid1, true, 'First signature should be valid');
  assert.strictEqual(isValid2, true, 'Second signature should be valid');
});

test('NEGATIVE: Verification with wrong public key', () => {
  const service = new VerifiableCredentialService();
  
  // Generate two different key pairs
  const keyPair1 = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });
  
  const keyPair2 = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });

  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/9999')
    .issuer('https://example.edu/issuers/11111')
    .issuanceDate('2022-12-01T09:15:00Z')
    .credentialSubject({
      id: 'did:example:mnopqr345678',
      status: 'Verified Graduate'
    })
    .build();

  // Sign with first key pair
  const signedVc = service.sign(vc, keyPair1.privateKey);
  
  // Try to verify with second key pair (should fail)
  const isValid = service.verify(signedVc, keyPair2.publicKey);
  assert.strictEqual(isValid, false, 'Verification should fail with wrong public key');
});

test('NEGATIVE: Tampered signature', () => {
  const service = new VerifiableCredentialService();
  
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });

  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/5555')
    .issuer('https://example.edu/issuers/44444')
    .issuanceDate('2019-03-15T14:45:00Z')
    .credentialSubject({
      id: 'did:example:stuvwx901234',
      certification: 'Blockchain Fundamentals Certificate'
    })
    .build();

  // Sign the VC
  const signedVc = service.sign(vc, privateKey);
  
  // Tamper with the signature
  const originalProofValue = signedVc.proof.proofValue;
  signedVc.proof.proofValue = originalProofValue.substring(0, originalProofValue.length - 5) + 'XXXXX';
  
  // Verification should fail
  const isValid = service.verify(signedVc, publicKey);
  assert.strictEqual(isValid, false, 'Verification should fail with tampered signature');
});

test('NEGATIVE: Missing proof', () => {
  const service = new VerifiableCredentialService();
  
  const { publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });

  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/1111')
    .issuer('https://example.edu/issuers/22222')
    .issuanceDate('2018-07-20T11:30:00Z')
    .credentialSubject({
      id: 'did:example:yzabcd567890',
      membership: 'Premium Member'
    })
    .build();

  // Try to verify unsigned VC
  const isValid = service.verify(vc, publicKey);
  assert.strictEqual(isValid, false, 'Verification should fail without proof');
});

test('NEGATIVE: Empty proof object', () => {
  const service = new VerifiableCredentialService();
  
  const { publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });

  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/2222')
    .issuer('https://example.edu/issuers/33333')
    .issuanceDate('2017-11-10T16:20:00Z')
    .credentialSubject({
      id: 'did:example:efghij123456',
      level: 'Expert'
    })
    .build();

  // Add empty proof
  vc.proof = {};
  
  // Try to verify VC with empty proof
  const isValid = service.verify(vc, publicKey);
  assert.strictEqual(isValid, false, 'Verification should fail with empty proof');
});

test('NEGATIVE: Proof without proofValue', () => {
  const service = new VerifiableCredentialService();
  
  const { publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });

  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/3333')
    .issuer('https://example.edu/issuers/44444')
    .issuanceDate('2016-05-05T08:10:00Z')
    .credentialSubject({
      id: 'did:example:klmnop789012',
      rank: 'Gold'
    })
    .build();

  // Add proof without proofValue
  const proof = new Proof(
    'EcdsaSecp256r1Signature2019',
    new Date().toISOString(),
    'did:example:123#key-1',
    'assertionMethod',
    null // No proofValue
  );
  vc.proof = proof.toJSON();
  
  // Try to verify VC with proof but no proofValue
  const isValid = service.verify(vc, publicKey);
  assert.strictEqual(isValid, false, 'Verification should fail without proofValue');
});

test('POSITIVE: Proof structure validation', () => {
  const proof = new Proof(
    'EcdsaSecp256r1Signature2019',
    '2023-01-01T10:00:00Z',
    'did:example:123#key-1',
    'assertionMethod',
    'MEUCIQD...' // Sample proofValue
  );

  // Test getters
  assert.strictEqual(proof.getType(), 'EcdsaSecp256r1Signature2019');
  assert.strictEqual(proof.getCreated(), '2023-01-01T10:00:00Z');
  assert.strictEqual(proof.getVerificationMethod(), 'did:example:123#key-1');
  assert.strictEqual(proof.getProofPurpose(), 'assertionMethod');
  assert.strictEqual(proof.getProofValue(), 'MEUCIQD...');

  // Test setters
  proof.setType('NewType');
  proof.setCreated('2023-12-31T23:59:59Z');
  proof.setVerificationMethod('did:example:456#key-2');
  proof.setProofPurpose('authentication');
  proof.setProofValue('NEWVALUE');

  assert.strictEqual(proof.getType(), 'NewType');
  assert.strictEqual(proof.getCreated(), '2023-12-31T23:59:59Z');
  assert.strictEqual(proof.getVerificationMethod(), 'did:example:456#key-2');
  assert.strictEqual(proof.getProofPurpose(), 'authentication');
  assert.strictEqual(proof.getProofValue(), 'NEWVALUE');

  // Test toJSON
  const jsonProof = proof.toJSON();
  assert.strictEqual(jsonProof.type, 'NewType');
  assert.strictEqual(jsonProof.created, '2023-12-31T23:59:59Z');
  assert.strictEqual(jsonProof.verificationMethod, 'did:example:456#key-2');
  assert.strictEqual(jsonProof.proofPurpose, 'authentication');
  assert.strictEqual(jsonProof.proofValue, 'NEWVALUE');

  // Test toString
  const stringProof = proof.toString();
  assert.ok(stringProof.includes('NewType'));
  assert.ok(stringProof.includes('2023-12-31T23:59:59Z'));
  assert.ok(stringProof.includes('did:example:456#key-2'));
  assert.ok(stringProof.includes('authentication'));
  assert.ok(stringProof.includes('NEWVALUE'));
});

test('POSITIVE: Generate key pair helper', () => {
  const keyPair = VerifiableCredentialService.generateKeyPair();
  
  // Check that both keys exist and are strings
  assert.ok(keyPair.publicKey, 'Public key should exist');
  assert.ok(keyPair.privateKey, 'Private key should exist');
  assert.ok(typeof keyPair.publicKey === 'string', 'Public key should be a string');
  assert.ok(typeof keyPair.privateKey === 'string', 'Private key should be a string');
  
  // Check that keys are different
  assert.notStrictEqual(keyPair.publicKey, keyPair.privateKey, 'Public and private keys should be different');
  
  // Test that keys can be used for signing/verification
  const service = new VerifiableCredentialService();
  
  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/test')
    .issuer('https://example.edu/issuers/test')
    .issuanceDate('2023-06-01T12:00:00Z')
    .credentialSubject({
      id: 'did:example:test',
      test: 'test'
    })
    .build();

  const signedVc = service.sign(vc, keyPair.privateKey);
  const isValid = service.verify(signedVc, keyPair.publicKey);
  assert.strictEqual(isValid, true, 'Generated keys should work for signing and verification');
});

test('POSITIVE: Create wallet helper', () => {
  const wallet = VerifiableCredentialService.createWallet();
  
  // Check wallet structure
  assert.ok(wallet.did, 'Wallet should have DID');
  assert.ok(wallet.publicKey, 'Wallet should have public key');
  assert.ok(wallet.privateKey, 'Wallet should have private key');
  
  // Check that DID is valid format
  assert.ok(wallet.did.startsWith('did:example:'), 'DID should have correct format');
  
  // Check that keys are strings
  assert.ok(typeof wallet.publicKey === 'string', 'Public key should be a string');
  assert.ok(typeof wallet.privateKey === 'string', 'Private key should be a string');
  
  // Test that wallet keys work
  const service = new VerifiableCredentialService();
  
  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/wallet-test')
    .issuer(wallet.did)
    .issuanceDate('2023-06-01T12:00:00Z')
    .credentialSubject({
      id: 'did:example:wallet-test',
      wallet: 'test'
    })
    .build();

  const signedVc = service.sign(vc, wallet.privateKey);
  const isValid = service.verify(signedVc, wallet.publicKey);
  assert.strictEqual(isValid, true, 'Wallet keys should work for signing and verification');
});