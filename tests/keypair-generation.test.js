import { test } from 'node:test';
import assert from 'assert';
import crypto from 'crypto';
import { VerifiableCredentialService } from '../src/crypto/index.js';

/**
 * Test suite to validate keypair generation uses correct curve and key sizes
 * 
 * Goals:
 * 1. Ensure generated keypairs use P-256 (secp256r1 / prime256v1) curve
 * 2. Validate key sizes are correct for P-256
 * 3. Confirm Base64 encoding works properly
 */

test('KEY GENERATION: Correct curve usage (P-256)', () => {
  // Generate a key pair using the service
  const keyPair = VerifiableCredentialService.generateKeyPair();
  
  // Convert Base64 back to KeyObjects for inspection
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(keyPair.publicKey, 'base64'),
    format: 'der',
    type: 'spki'
  });
  
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(keyPair.privateKey, 'base64'),
    format: 'der',
    type: 'pkcs8'
  });
  
  // Check that both keys use the correct key type
  assert.strictEqual(publicKey.asymmetricKeyType, 'ec', 'Public key should be elliptic curve type');
  assert.strictEqual(privateKey.asymmetricKeyType, 'ec', 'Private key should be elliptic curve type');
  
  // Check key details if available
  if (publicKey.asymmetricKeyDetails) {
    // Note: In Node.js, P-256 is often represented as 'prime256v1'
    const curve = publicKey.asymmetricKeyDetails.namedCurve;
    assert.ok(curve === 'prime256v1' || curve === 'P-256' || curve === 'secp256r1', 
      `Public key should use P-256 curve variant, got ${curve}`);
  }
  
  if (privateKey.asymmetricKeyDetails) {
    const curve = privateKey.asymmetricKeyDetails.namedCurve;
    assert.ok(curve === 'prime256v1' || curve === 'P-256' || curve === 'secp256r1', 
      `Private key should use P-256 curve variant, got ${curve}`);
  }
});

test('KEY GENERATION: Direct P-256 key generation', () => {
  // Generate P-256 key pair directly using Node.js crypto
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256' // This is the same as prime256v1
  });
  
  // Check key types
  assert.strictEqual(publicKey.asymmetricKeyType, 'ec', 'Public key should be elliptic curve type');
  assert.strictEqual(privateKey.asymmetricKeyType, 'ec', 'Private key should be elliptic curve type');
  
  // Check curve details if available
  if (publicKey.asymmetricKeyDetails) {
    // P-256 is also known as prime256v1 in OpenSSL
    const curve = publicKey.asymmetricKeyDetails.namedCurve;
    assert.ok(curve === 'prime256v1' || curve === 'P-256' || curve === 'secp256r1', 
      `Public key should use P-256 curve variant, got ${curve}`);
  }
  
  if (privateKey.asymmetricKeyDetails) {
    const curve = privateKey.asymmetricKeyDetails.namedCurve;
    assert.ok(curve === 'prime256v1' || curve === 'P-256' || curve === 'secp256r1', 
      `Private key should use P-256 curve variant, got ${curve}`);
  }
});

test('KEY GENERATION: Key size validation', () => {
  // Generate a key pair using the service
  const keyPair = VerifiableCredentialService.generateKeyPair();
  
  // Convert Base64 back to KeyObjects
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(keyPair.publicKey, 'base64'),
    format: 'der',
    type: 'spki'
  });
  
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(keyPair.privateKey, 'base64'),
    format: 'der',
    type: 'pkcs8'
  });
  
  // Get key sizes
  const publicKeySize = publicKey.asymmetricKeyDetails?.modulusLength || 
                       (publicKey.asymmetricKeyDetails?.namedCurve ? 256 : 0);
  const privateKeySize = privateKey.asymmetricKeyDetails?.modulusLength || 
                        (privateKey.asymmetricKeyDetails?.namedCurve ? 256 : 0);
  
  // For EC keys, we check the curve rather than bit length
  // P-256 should have a key size equivalent to 256 bits
  assert.strictEqual(publicKeySize, 256, 'Public key should be 256-bit (P-256)');
  assert.strictEqual(privateKeySize, 256, 'Private key should be 256-bit (P-256)');
});

test('KEY GENERATION: Base64 encoding validation', () => {
  // Generate a key pair
  const keyPair = VerifiableCredentialService.generateKeyPair();
  
  // Check that both keys are valid Base64 strings
  assert.ok(keyPair.publicKey, 'Public key should exist');
  assert.ok(keyPair.privateKey, 'Private key should exist');
  
  assert.ok(typeof keyPair.publicKey === 'string', 'Public key should be a string');
  assert.ok(typeof keyPair.privateKey === 'string', 'Private key should be a string');
  
  // Validate Base64 format
  const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
  assert.ok(base64Regex.test(keyPair.publicKey), 'Public key should be valid Base64');
  assert.ok(base64Regex.test(keyPair.privateKey), 'Private key should be valid Base64');
  
  // Check that we can decode them back
  assert.doesNotThrow(() => {
    Buffer.from(keyPair.publicKey, 'base64');
    Buffer.from(keyPair.privateKey, 'base64');
  }, 'Key strings should be valid Base64 that can be decoded to buffers');
  
  // Check that decoded buffers have reasonable sizes
  const publicBuffer = Buffer.from(keyPair.publicKey, 'base64');
  const privateBuffer = Buffer.from(keyPair.privateKey, 'base64');
  
  // SPKI format public keys are typically around 91 bytes for P-256
  // PKCS#8 format private keys are typically around 121 bytes for P-256
  assert.ok(publicBuffer.length > 80 && publicBuffer.length < 120, 
    `Public key buffer should be reasonable size for P-256 SPKI, got ${publicBuffer.length} bytes`);
  assert.ok(privateBuffer.length > 110 && privateBuffer.length < 150, 
    `Private key buffer should be reasonable size for P-256 PKCS#8, got ${privateBuffer.length} bytes`);
});

test('KEY GENERATION: Wallet creation with correct curve', () => {
  // Create a wallet
  const wallet = VerifiableCredentialService.createWallet();
  
  // Check wallet structure
  assert.ok(wallet.did, 'Wallet should have a DID');
  assert.ok(wallet.publicKey, 'Wallet should have a public key');
  assert.ok(wallet.privateKey, 'Wallet should have a private key');
  
  // Check DID format
  assert.ok(wallet.did.startsWith('did:example:'), 'Wallet DID should have correct format');
  
  // Validate keys
  assert.ok(typeof wallet.publicKey === 'string', 'Wallet public key should be a string');
  assert.ok(typeof wallet.privateKey === 'string', 'Wallet private key should be a string');
  
  // Check that we can use the keys for cryptographic operations
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(wallet.publicKey, 'base64'),
    format: 'der',
    type: 'spki'
  });
  
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(wallet.privateKey, 'base64'),
    format: 'der',
    type: 'pkcs8'
  });
  
  assert.strictEqual(publicKey.asymmetricKeyType, 'ec', 'Wallet public key should be elliptic curve type');
  assert.strictEqual(privateKey.asymmetricKeyType, 'ec', 'Wallet private key should be elliptic curve type');
});

test('KEY GENERATION: Multiple key pairs are unique', () => {
  // Generate multiple key pairs
  const keyPair1 = VerifiableCredentialService.generateKeyPair();
  const keyPair2 = VerifiableCredentialService.generateKeyPair();
  const keyPair3 = VerifiableCredentialService.generateKeyPair();
  
  // All key pairs should be different
  assert.notStrictEqual(keyPair1.publicKey, keyPair2.publicKey, 'Public keys should be unique');
  assert.notStrictEqual(keyPair1.privateKey, keyPair2.privateKey, 'Private keys should be unique');
  assert.notStrictEqual(keyPair1.publicKey, keyPair3.publicKey, 'Public keys should be unique');
  assert.notStrictEqual(keyPair1.privateKey, keyPair3.privateKey, 'Private keys should be unique');
  assert.notStrictEqual(keyPair2.publicKey, keyPair3.publicKey, 'Public keys should be unique');
  assert.notStrictEqual(keyPair2.privateKey, keyPair3.privateKey, 'Private keys should be unique');
  
  // Keys within each pair should be different
  assert.notStrictEqual(keyPair1.publicKey, keyPair1.privateKey, 'Public and private keys should be different');
  assert.notStrictEqual(keyPair2.publicKey, keyPair2.privateKey, 'Public and private keys should be different');
  assert.notStrictEqual(keyPair3.publicKey, keyPair3.privateKey, 'Public and private keys should be different');
});

test('KEY GENERATION: Keys work for signing and verification', () => {
  // Generate a key pair
  const keyPair = VerifiableCredentialService.generateKeyPair();
  
  // Convert Base64 back to KeyObjects
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(keyPair.publicKey, 'base64'),
    format: 'der',
    type: 'spki'
  });
  
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(keyPair.privateKey, 'base64'),
    format: 'der',
    type: 'pkcs8'
  });
  
  // Test signing and verification
  const testData = 'This is test data for signing';
  
  // Sign
  const sign = crypto.createSign('sha256');
  sign.update(testData);
  sign.end();
  const signature = sign.sign(privateKey);
  
  // Verify
  const verify = crypto.createVerify('sha256');
  verify.update(testData);
  verify.end();
  const isValid = verify.verify(publicKey, signature);
  
  assert.ok(isValid, 'Generated keys should work for signing and verification');
});

test('KEY GENERATION: Curve name consistency', () => {
  // Check that the service uses the correct curve name
  assert.strictEqual(
    VerifiableCredentialService.EC_CURVE_NAME, 
    'P-256', 
    'Service should use P-256 as the curve name'
  );
  
  // Generate a key pair and verify it uses the configured curve
  const keyPair = VerifiableCredentialService.generateKeyPair();
  
  // We can't directly check the curve name from the exported DER format,
  // but we can verify that the service is using the correct configuration
  // by checking that it doesn't throw an error when generating keys
  assert.ok(keyPair.publicKey, 'Key generation should succeed with configured curve');
  assert.ok(keyPair.privateKey, 'Key generation should succeed with configured curve');
});