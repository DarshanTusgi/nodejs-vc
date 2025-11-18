import crypto from 'crypto';
import { 
  VerifiableCredentialService, 
  VCBuilder, 
  JSONLDCanon, 
  KeyUtils 
} from './index.js';

function main() {
  try {
    // Create the service
    const service = new VerifiableCredentialService();
    
    // Method 1: Generate EC key pair for demonstration using Node.js crypto
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256'
    });
    
    // Create a sample verifiable credential using VCBuilder
    const vc = new VCBuilder()
      .addContext('https://www.w3.org/2018/credentials/v1')
      .addType('VerifiableCredential')
      .id('http://example.edu/credentials/123')
      .issuer('did:example:123456789abcdefghi')
      .issuanceDate('2023-06-01T12:00:00Z')
      .credentialSubject({
        id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
        name: 'Jane Doe',
        degree: 'Bachelor of Science and Arts'
      })
      .build();
    
    console.log('Original VC:', vc.toString());
    
    // Show canonicalization using JSONLDCanon helper
    const canonicalVc = JSONLDCanon.canonicalize(vc);
    console.log('\nCanonicalized VC:', canonicalVc);
    
    // Sign the VC with KeyObject
    const signedVc = service.sign(vc, privateKey);
    
    console.log('\nSigned VC (with KeyObject):', JSON.stringify(signedVc, null, 2));
    
    // Verify the signed VC with KeyObject
    const isValid1 = service.verify(signedVc, publicKey);
    console.log('\nVerification result (with KeyObject):', isValid1 ? 'VALID' : 'INVALID');
    
    // Method 2: Using Base64-encoded keys (for saved keys)
    console.log('\n--- Using Base64-encoded keys ---');
    
    // Generate a new key pair and export as Base64
    const wallet = VerifiableCredentialService.createWallet();
    console.log('Generated wallet DID:', wallet.did);
    
    // Sign the VC with Base64 private key
    const signedVc2 = service.sign(vc, wallet.privateKey);
    
    console.log('\nSigned VC (with Base64 key):', JSON.stringify(signedVc2, null, 2));
    
    // Verify the signed VC with Base64 public key
    const isValid2 = service.verify(signedVc2, wallet.publicKey);
    console.log('\nVerification result (with Base64 key):', isValid2 ? 'VALID' : 'INVALID');
    
    // Method 3: Converting existing keys to Base64 for storage
    console.log('\n--- Converting existing keys to Base64 ---');
    
    // Export the original keys as Base64 for storage
    const publicKeyBase64 = publicKey.export({
      format: 'der',
      type: 'spki'
    }).toString('base64');
    
    const privateKeyBase64 = privateKey.export({
      format: 'der',
      type: 'pkcs8'
    }).toString('base64');
    
    console.log('Public Key (Base64):', publicKeyBase64);
    console.log('Private Key (Base64):', privateKeyBase64);
    
    // Sign with Base64 keys
    const signedVc3 = service.sign(vc, privateKeyBase64);
    
    console.log('\nSigned VC (with converted Base64 key):', JSON.stringify(signedVc3, null, 2));
    
    // Verify with Base64 keys
    const isValid3 = service.verify(signedVc3, publicKeyBase64);
    console.log('\nVerification result (with converted Base64 key):', isValid3 ? 'VALID' : 'INVALID');
    
    console.log('\nExample completed successfully!');
    
  } catch (error) {
    console.error('Error in example:', error.message);
    process.exit(1);
  }
}

// Run the example
main();