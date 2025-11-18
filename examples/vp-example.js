import { VCBuilder, VPBuilder, VerifiableCredentialService } from '../src/index.js';

// Create service
const service = new VerifiableCredentialService();

// Generate key pairs for issuer and holder
const issuerWallet = VerifiableCredentialService.createWallet();
const holderWallet = VerifiableCredentialService.createWallet();

// Step 1: Create and sign a Verifiable Credential
const vc = new VCBuilder()
  .context(['https://www.w3.org/ns/credentials/v2'])
  .type(['VerifiableCredential', 'UniversityDegreeCredential'])
  .id('http://example.edu/credentials/3732')
  .issuer(issuerWallet.did)
  .validFrom(new Date().toISOString())
  .credentialSubject({
    id: holderWallet.did,
    name: 'Alice Smith',
    degree: 'Bachelor of Science'
  })
  .build();

const signedVC = service.sign(vc.toJSON(), issuerWallet.privateKey);
console.log('VC is valid:', service.verify(signedVC, issuerWallet.publicKey));

// Step 2: Create a Verifiable Presentation containing the VC
const vp = new VPBuilder()
  .context(['https://www.w3.org/ns/credentials/v2'])
  .type(['VerifiablePresentation'])
  .id('http://example.edu/presentations/1')
  .holder(holderWallet.did)
  .addCredential(signedVC)
  .build();

// Step 3: Sign the VP with holder's private key
const signedVP = service.signPresentation(vp.toJSON(), holderWallet.privateKey);

// Step 4: Verify the VP signature
console.log('VP is valid:', service.verifyPresentation(signedVP, holderWallet.publicKey));

// Step 5: Verify the credentials inside the VP
signedVP.verifiableCredential.forEach((credential, index) => {
  const credValid = service.verify(credential, issuerWallet.publicKey);
  console.log(`Credential ${index + 1} is valid:`, credValid);
});
