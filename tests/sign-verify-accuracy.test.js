import { test } from 'node:test';
import assert from 'assert';
import crypto from 'crypto';
import { VerifiableCredentialService } from '../src/crypto/index.js';
import { VCBuilder } from '../src/builder/index.js';
import { Proof } from '../src/core/index.js';

/**
 * Strict accuracy test for EcdsaSecp256r1Signature2019 sign & verify operations
 * 
 * Goals:
 * 1. Verify compliance with EcdsaSecp256r1Signature2019 specification
 * 2. Validate signature format matches expected ES256/ECDSA P-256 format
 * 3. Confirm proof structure matches specification requirements
 * 4. Test interoperability with standard crypto libraries
 */

test('SIGN/VERIFY ACCURACY: EcdsaSecp256r1Signature2019 proof structure', () => {
  const service = new VerifiableCredentialService();
  const keyPair = VerifiableCredentialService.generateKeyPair();

  // Create a sample VC
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
  const signedVc = service.sign(vc, keyPair.privateKey);

  // Validate proof structure according to EcdsaSecp256r1Signature2019 spec
  assert.ok(signedVc.proof, 'Proof must be present');
  
  const proof = signedVc.proof;
  assert.strictEqual(proof.type, 'EcdsaSecp256r1Signature2019', 'Proof type must be EcdsaSecp256r1Signature2019');
  assert.ok(proof.created, 'Proof must have creation timestamp');
  assert.ok(proof.verificationMethod, 'Proof must have verification method');
  assert.ok(proof.proofPurpose, 'Proof must have purpose');
  assert.ok(proof.proofValue, 'Proof must have proofValue');
  
  // Validate timestamp format
  assert.doesNotThrow(() => {
    new Date(proof.created);
  }, 'Proof creation timestamp must be valid ISO date');
  
  // Validate proofValue format
  assert.ok(typeof proof.proofValue === 'string', 'Proof value must be a string');
  assert.ok(proof.proofValue.length > 0, 'Proof value must not be empty');
  
  // Validate Base64 format
  const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
  assert.ok(base64Regex.test(proof.proofValue), 'Proof value must be valid Base64');
  
  // Verify the signature
  const isValid = service.verify(signedVc, keyPair.publicKey);
  assert.ok(isValid, 'Signature must be valid');
});

test('SIGN/VERIFY ACCURACY: Signature format validation (ES256/ECDSA P-256)', async () => {
  const service = new VerifiableCredentialService();
  const keyPair = VerifiableCredentialService.generateKeyPair();

  // Create a sample VC
  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/test')
    .issuer('https://example.edu/issuers/test')
    .issuanceDate('2022-01-01T12:00:00Z')
    .credentialSubject({
      id: 'did:example:test',
      test: 'value'
    })
    .build();

  // Sign the VC
  const signedVc = service.sign(vc, keyPair.privateKey);
  const proofValue = signedVc.proof.proofValue;

  // Decode the signature to check its properties
  const signatureBuffer = Buffer.from(proofValue, 'base64');
  
  // ECDSA P-256 signatures are typically 64-72 bytes
  // DER encoded signatures can be longer due to ASN.1 encoding
  assert.ok(signatureBuffer.length >= 64, `Signature should be at least 64 bytes, got ${signatureBuffer.length}`);
  assert.ok(signatureBuffer.length <= 80, `Signature should be reasonable size, got ${signatureBuffer.length} bytes`);
  
  // Log signature info for analysis
  console.log(`Signature length: ${signatureBuffer.length} bytes`);
  console.log(`Signature (hex): ${signatureBuffer.toString('hex')}`);
  console.log(`Signature (base64): ${proofValue}`);
  
  // Verify with standard Node.js crypto
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(keyPair.publicKey, 'base64'),
    format: 'der',
    type: 'spki'
  });

  // Recreate the canonicalized data for verification
  const vcWithoutProof = JSON.parse(JSON.stringify(vc));
  delete vcWithoutProof.proof;
  
  // Import JSONLDCanon to canonicalize
  const { JSONLDCanon } = await import('../src/crypto/index.js');
  const canonicalVc = JSONLDCanon.canonicalize(vcWithoutProof, true);
  
  // Verify with standard crypto
  const verify = crypto.createVerify('sha256');
  verify.update(canonicalVc);
  verify.end();
  const isValid = verify.verify(publicKey, signatureBuffer);
  
  assert.ok(isValid, 'Signature must be valid when verified with standard Node.js crypto');
});

test('SIGN/VERIFY ACCURACY: Non-deterministic signature generation', () => {
  const service = new VerifiableCredentialService();
  const keyPair = VerifiableCredentialService.generateKeyPair();

  // Create identical VCs
  const vc1 = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/deterministic')
    .issuer('https://example.edu/issuers/deterministic')
    .issuanceDate('2022-01-01T12:00:00Z')
    .credentialSubject({
      id: 'did:example:deterministic',
      test: 'value'
    })
    .build();

  const vc2 = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/deterministic')
    .issuer('https://example.edu/issuers/deterministic')
    .issuanceDate('2022-01-01T12:00:00Z')
    .credentialSubject({
      id: 'did:example:deterministic',
      test: 'value'
    })
    .build();

  // Sign both VCs
  const signedVc1 = service.sign(vc1, keyPair.privateKey);
  const signedVc2 = service.sign(vc2, keyPair.privateKey);

  // Signatures should be different for identical inputs (ECDSA uses random nonce)
  assert.notStrictEqual(
    signedVc1.proof.proofValue,
    signedVc2.proof.proofValue,
    'Signatures for identical VCs should be different (ECDSA uses random nonce)'
  );
  
  // But both should be valid
  const isValid1 = service.verify(signedVc1, keyPair.publicKey);
  const isValid2 = service.verify(signedVc2, keyPair.publicKey);
  
  assert.ok(isValid1, 'First signature should be valid');
  assert.ok(isValid2, 'Second signature should be valid');
});

test('SIGN/VERIFY ACCURACY: Proof creation timestamp validation', () => {
  const service = new VerifiableCredentialService();
  const keyPair = VerifiableCredentialService.generateKeyPair();

  // Create a VC
  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/timestamp')
    .issuer('https://example.edu/issuers/timestamp')
    .issuanceDate('2022-01-01T12:00:00Z')
    .credentialSubject({
      id: 'did:example:timestamp',
      test: 'value'
    })
    .build();

  // Sign the VC
  const signedVc = service.sign(vc, keyPair.privateKey);
  const proof = signedVc.proof;
  
  // Validate timestamp
  assert.ok(proof.created, 'Proof must have creation timestamp');
  assert.ok(typeof proof.created === 'string', 'Timestamp must be a string');
  
  // Validate ISO 8601 format
  const isoRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
  assert.ok(isoRegex.test(proof.created), 'Timestamp must be in ISO 8601 format');
  
  // Validate it's a recent timestamp
  const createdTime = new Date(proof.created);
  const now = new Date();
  const timeDiff = now.getTime() - createdTime.getTime();
  
  // Should be within a few seconds of now
  assert.ok(timeDiff >= 0, 'Timestamp should not be in the future');
  assert.ok(timeDiff < 60000, 'Timestamp should be recent (within 1 minute)');
});

test('SIGN/VERIFY ACCURACY: Proof purpose validation', () => {
  const service = new VerifiableCredentialService();
  const keyPair = VerifiableCredentialService.generateKeyPair();

  // Create a VC
  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/purpose')
    .issuer('https://example.edu/issuers/purpose')
    .issuanceDate('2022-01-01T12:00:00Z')
    .credentialSubject({
      id: 'did:example:purpose',
      test: 'value'
    })
    .build();

  // Sign the VC
  const signedVc = service.sign(vc, keyPair.privateKey);
  const proof = signedVc.proof;
  
  // Validate proof purpose
  assert.ok(proof.proofPurpose, 'Proof must have purpose');
  assert.ok(
    ['assertionMethod', 'authentication', 'capabilityInvocation', 'capabilityDelegation'].includes(proof.proofPurpose),
    'Proof purpose must be a valid LD proof purpose'
  );
  
  // Default should be assertionMethod
  assert.strictEqual(
    proof.proofPurpose, 
    'assertionMethod', 
    'Default proof purpose should be assertionMethod'
  );
});

test('SIGN/VERIFY ACCURACY: Verification method validation', () => {
  const service = new VerifiableCredentialService();
  const keyPair = VerifiableCredentialService.generateKeyPair();

  // Create a VC
  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/method')
    .issuer('https://example.edu/issuers/method')
    .issuanceDate('2022-01-01T12:00:00Z')
    .credentialSubject({
      id: 'did:example:method',
      test: 'value'
    })
    .build();

  // Sign the VC
  const signedVc = service.sign(vc, keyPair.privateKey);
  const proof = signedVc.proof;
  
  // Validate verification method
  assert.ok(proof.verificationMethod, 'Proof must have verification method');
  assert.ok(typeof proof.verificationMethod === 'string', 'Verification method must be a string');
  assert.ok(proof.verificationMethod.length > 0, 'Verification method must not be empty');
  
  // Should be a DID URL format
  assert.ok(
    proof.verificationMethod.startsWith('did:'), 
    'Verification method should be a DID URL'
  );
});

test('SIGN/VERIFY ACCURACY: Interoperability with standard crypto', async () => {
  // Generate keys using standard Node.js crypto
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });

  // Test data
  const testData = '{"test":"data"}';
  
  // Sign with standard crypto
  const sign = crypto.createSign('sha256');
  sign.update(testData);
  sign.end();
  const signature = sign.sign(privateKey);
  
  // Verify with standard crypto
  const verify = crypto.createVerify('sha256');
  verify.update(testData);
  verify.end();
  const isValid = verify.verify(publicKey, signature);
  
  assert.ok(isValid, 'Standard crypto signing/verification should work');
  
  // Convert keys to our format
  const publicKeyBase64 = publicKey.export({
    format: 'der',
    type: 'spki'
  }).toString('base64');

  const privateKeyBase64 = privateKey.export({
    format: 'der',
    type: 'pkcs8'
  }).toString('base64');
  
  // Test with our service
  const service = new VerifiableCredentialService();
  const vc = new VCBuilder()
    .addContext('https://www.w3.org/2018/credentials/v1')
    .addType('VerifiableCredential')
    .id('http://example.edu/credentials/interop')
    .issuer('https://example.edu/issuers/interop')
    .issuanceDate('2022-01-01T12:00:00Z')
    .credentialSubject({
      id: 'did:example:interop',
      test: 'interop'
    })
    .build();

  // Sign with our service using the standard keys
  const signedVc = service.sign(vc, privateKeyBase64);
  
  // Verify with our service
  const isValidWithService = service.verify(signedVc, publicKeyBase64);
  assert.ok(isValidWithService, 'Our service should work with standard P-256 keys');
  
  // Verify signature manually with standard crypto
  const signatureBuffer = Buffer.from(signedVc.proof.proofValue, 'base64');
  
  // Recreate canonicalized data
  const vcWithoutProof = JSON.parse(JSON.stringify(vc));
  delete vcWithoutProof.proof;
  
  // Import JSONLDCanon to canonicalize
  const { JSONLDCanon } = await import('../src/crypto/index.js');
  const canonicalVc = JSONLDCanon.canonicalize(vcWithoutProof, true);
  
  // Verify with standard crypto
  const manualVerify = crypto.createVerify('sha256');
  manualVerify.update(canonicalVc);
  manualVerify.end();
  const manuallyValid = manualVerify.verify(publicKey, signatureBuffer);
  
  assert.ok(manuallyValid, 'Signatures should be verifiable with standard crypto');
});

test('SIGN/VERIFY ACCURACY: FIPS compliance audit logging', () => {
  // Capture console output
  const originalLog = console.log;
  const logs = [];
  console.log = (...args) => {
    logs.push(args.join(' '));
    originalLog(...args);
  };

  try {
    const service = new VerifiableCredentialService();
    const keyPair = VerifiableCredentialService.generateKeyPair();

    // Create a VC
    const vc = new VCBuilder()
      .addContext('https://www.w3.org/2018/credentials/v1')
      .addType('VerifiableCredential')
      .id('http://example.edu/credentials/fips')
      .issuer('https://example.edu/issuers/fips')
      .issuanceDate('2022-01-01T12:00:00Z')
      .credentialSubject({
        id: 'did:example:fips',
        test: 'fips'
      })
      .build();

    // Sign the VC
    const signedVc = service.sign(vc, keyPair.privateKey);
    
    // Verify the VC
    service.verify(signedVc, keyPair.publicKey);

    // Check for FIPS audit logs
    const signAuditLogs = logs.filter(log => log.includes('[FIPS AUDIT] Signed'));
    const verifyAuditLogs = logs.filter(log => log.includes('[FIPS AUDIT] Verified'));
    
    assert.ok(signAuditLogs.length > 0, 'Should have FIPS audit log for signing');
    assert.ok(verifyAuditLogs.length > 0, 'Should have FIPS audit log for verification');
    assert.ok(signAuditLogs[0].includes('ECDSA P-256'), 'Sign audit log should mention ECDSA P-256');
    assert.ok(verifyAuditLogs[0].includes('VC signature'), 'Verify audit log should mention VC signature');
    
  } finally {
    // Restore console.log
    console.log = originalLog;
  }
});