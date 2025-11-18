import { test } from 'node:test';
import assert from 'node:assert';
import { VCBuilder, VPBuilder, VerifiableCredentialService } from '../src/index.js';

test('VP - Basic sign and verify flow', () => {
  const service = new VerifiableCredentialService();
  const issuerWallet = VerifiableCredentialService.createWallet();
  const holderWallet = VerifiableCredentialService.createWallet();

  // Create and sign a VC
  const vc = new VCBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .addContext('https://www.w3.org/2018/credentials/v1')
    .type(['VerifiableCredential'])
    .id('http://example.edu/credentials/1')
    .issuer(issuerWallet.did)
    .validFrom(new Date().toISOString())
    .credentialSubject({ id: holderWallet.did, name: 'Alice' })
    .build();

  const signedVC = service.sign(vc.toJSON(), issuerWallet.privateKey);

  // Create and sign a VP
  const vp = new VPBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiablePresentation'])
    .id('http://example.edu/presentations/1')
    .holder(holderWallet.did)
    .addCredential(signedVC)
    .build();

  const signedVP = service.signPresentation(vp.toJSON(), holderWallet.privateKey);

  // Verify VP
  const isValid = service.verifyPresentation(signedVP, holderWallet.publicKey);
  assert.strictEqual(isValid, true, 'VP signature should be valid');
});

test('VP - Verify with wrong public key', () => {
  const service = new VerifiableCredentialService();
  const issuerWallet = VerifiableCredentialService.createWallet();
  const holderWallet = VerifiableCredentialService.createWallet();
  const wrongWallet = VerifiableCredentialService.createWallet();

  const vc = new VCBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiableCredential'])
    .id('http://example.edu/credentials/2')
    .issuer(issuerWallet.did)
    .validFrom(new Date().toISOString())
    .credentialSubject({ id: holderWallet.did })
    .build();

  const signedVC = service.sign(vc.toJSON(), issuerWallet.privateKey);

  const vp = new VPBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiablePresentation'])
    .holder(holderWallet.did)
    .addCredential(signedVC)
    .build();

  const signedVP = service.signPresentation(vp.toJSON(), holderWallet.privateKey);

  // Verify with wrong key
  const isValid = service.verifyPresentation(signedVP, wrongWallet.publicKey);
  assert.strictEqual(isValid, false, 'VP signature should be invalid with wrong key');
});

test('VP - Multiple credentials in presentation', () => {
  const service = new VerifiableCredentialService();
  const issuerWallet1 = VerifiableCredentialService.createWallet();
  const issuerWallet2 = VerifiableCredentialService.createWallet();
  const holderWallet = VerifiableCredentialService.createWallet();

  // Create two VCs from different issuers
  const vc1 = new VCBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiableCredential', 'DegreeCredential'])
    .id('http://example.edu/credentials/1')
    .issuer(issuerWallet1.did)
    .validFrom(new Date().toISOString())
    .credentialSubject({ id: holderWallet.did, degree: 'BS' })
    .build();

  const vc2 = new VCBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiableCredential', 'EmploymentCredential'])
    .id('http://example.com/credentials/1')
    .issuer(issuerWallet2.did)
    .validFrom(new Date().toISOString())
    .credentialSubject({ id: holderWallet.did, position: 'Engineer' })
    .build();

  const signedVC1 = service.sign(vc1.toJSON(), issuerWallet1.privateKey);
  const signedVC2 = service.sign(vc2.toJSON(), issuerWallet2.privateKey);

  // Create VP with multiple credentials
  const vp = new VPBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiablePresentation'])
    .holder(holderWallet.did)
    .verifiableCredential([signedVC1, signedVC2])
    .build();

  const signedVP = service.signPresentation(vp.toJSON(), holderWallet.privateKey);

  // Verify VP
  assert.strictEqual(service.verifyPresentation(signedVP, holderWallet.publicKey), true);
  
  // Verify both credentials inside
  assert.strictEqual(service.verify(signedVP.verifiableCredential[0], issuerWallet1.publicKey), true);
  assert.strictEqual(service.verify(signedVP.verifiableCredential[1], issuerWallet2.publicKey), true);
  
  // Check structure
  assert.strictEqual(signedVP.verifiableCredential.length, 2);
});

test('VP - Builder validation - missing holder', () => {
  const issuerWallet = VerifiableCredentialService.createWallet();
  const holderWallet = VerifiableCredentialService.createWallet();
  const service = new VerifiableCredentialService();

  const vc = new VCBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiableCredential'])
    .issuer(issuerWallet.did)
    .validFrom(new Date().toISOString())
    .credentialSubject({ id: holderWallet.did })
    .build();

  const signedVC = service.sign(vc.toJSON(), issuerWallet.privateKey);

  assert.throws(() => {
    new VPBuilder()
      .context(['https://www.w3.org/ns/credentials/v2'])
      .type(['VerifiablePresentation'])
      // Missing holder
      .addCredential(signedVC)
      .build();
  }, /Holder is required/);
});

test('VP - Builder validation - missing credentials', () => {
  const holderWallet = VerifiableCredentialService.createWallet();

  assert.throws(() => {
    new VPBuilder()
      .context(['https://www.w3.org/ns/credentials/v2'])
      .type(['VerifiablePresentation'])
      .holder(holderWallet.did)
      // Missing credentials
      .build();
  }, /At least one verifiable credential is required/);
});

test('VP - Proof structure validation', () => {
  const service = new VerifiableCredentialService();
  const issuerWallet = VerifiableCredentialService.createWallet();
  const holderWallet = VerifiableCredentialService.createWallet();

  const vc = new VCBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiableCredential'])
    .issuer(issuerWallet.did)
    .validFrom(new Date().toISOString())
    .credentialSubject({ id: holderWallet.did })
    .build();

  const signedVC = service.sign(vc.toJSON(), issuerWallet.privateKey);

  const vp = new VPBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiablePresentation'])
    .holder(holderWallet.did)
    .addCredential(signedVC)
    .build();

  const signedVP = service.signPresentation(vp.toJSON(), holderWallet.privateKey);

  // Verify proof structure
  assert.ok(signedVP.proof, 'VP should have proof');
  assert.strictEqual(signedVP.proof.type, 'EcdsaSecp256r1Signature2019');
  assert.strictEqual(signedVP.proof.proofPurpose, 'authentication'); // VP uses authentication
  assert.ok(signedVP.proof.proofValue, 'Proof should have proofValue');
  assert.ok(signedVP.proof.created, 'Proof should have created timestamp');
  assert.ok(signedVP.proof.verificationMethod, 'Proof should have verificationMethod');
});

test('VP - Tampered VP detection', () => {
  const service = new VerifiableCredentialService();
  const issuerWallet = VerifiableCredentialService.createWallet();
  const holderWallet = VerifiableCredentialService.createWallet();

  const vc = new VCBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiableCredential'])
    .issuer(issuerWallet.did)
    .validFrom(new Date().toISOString())
    .credentialSubject({ id: holderWallet.did, name: 'Alice' })
    .build();

  const signedVC = service.sign(vc.toJSON(), issuerWallet.privateKey);

  const vp = new VPBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiablePresentation'])
    .holder(holderWallet.did)
    .addCredential(signedVC)
    .build();

  const signedVP = service.signPresentation(vp.toJSON(), holderWallet.privateKey);

  // Tamper with VP
  signedVP.holder = 'did:example:tampered';

  // Verification should fail
  const isValid = service.verifyPresentation(signedVP, holderWallet.publicKey);
  assert.strictEqual(isValid, false, 'Tampered VP should be invalid');
});

test('VP - Missing proof validation', () => {
  const service = new VerifiableCredentialService();
  const vp = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiablePresentation'],
    holder: 'did:example:holder',
    verifiableCredential: []
  };

  const holderWallet = VerifiableCredentialService.createWallet();
  const isValid = service.verifyPresentation(vp, holderWallet.publicKey);
  assert.strictEqual(isValid, false, 'VP without proof should be invalid');
});

test('VP - Context and type preservation', () => {
  const service = new VerifiableCredentialService();
  const issuerWallet = VerifiableCredentialService.createWallet();
  const holderWallet = VerifiableCredentialService.createWallet();

  const vc = new VCBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiableCredential'])
    .issuer(issuerWallet.did)
    .validFrom(new Date().toISOString())
    .credentialSubject({ id: holderWallet.did })
    .build();

  const signedVC = service.sign(vc.toJSON(), issuerWallet.privateKey);

  const vp = new VPBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .addContext('https://example.com/custom')
    .type(['VerifiablePresentation', 'CustomPresentation'])
    .holder(holderWallet.did)
    .addCredential(signedVC)
    .build();

  const signedVP = service.signPresentation(vp.toJSON(), holderWallet.privateKey);

  // Verify context and types are preserved
  assert.strictEqual(signedVP['@context'].length, 2);
  assert.ok(signedVP['@context'].includes('https://www.w3.org/ns/credentials/v2'));
  assert.ok(signedVP['@context'].includes('https://example.com/custom'));
  assert.ok(signedVP.type.includes('VerifiablePresentation'));
  assert.ok(signedVP.type.includes('CustomPresentation'));
});

test('VP - Base64 key support', () => {
  const service = new VerifiableCredentialService();
  const issuerWallet = VerifiableCredentialService.createWallet();
  const holderWallet = VerifiableCredentialService.createWallet();

  const vc = new VCBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiableCredential'])
    .issuer(issuerWallet.did)
    .validFrom(new Date().toISOString())
    .credentialSubject({ id: holderWallet.did })
    .build();

  const signedVC = service.sign(vc.toJSON(), issuerWallet.privateKey);

  const vp = new VPBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiablePresentation'])
    .holder(holderWallet.did)
    .addCredential(signedVC)
    .build();

  // Sign and verify with Base64 encoded keys (strings)
  const signedVP = service.signPresentation(vp.toJSON(), holderWallet.privateKey);
  const isValid = service.verifyPresentation(signedVP, holderWallet.publicKey);
  
  assert.strictEqual(isValid, true, 'VP should be valid with Base64 keys');
  assert.strictEqual(typeof holderWallet.privateKey, 'string');
  assert.strictEqual(typeof holderWallet.publicKey, 'string');
});

test('VP - VerifiablePresentation type auto-added', () => {
  const service = new VerifiableCredentialService();
  const issuerWallet = VerifiableCredentialService.createWallet();
  const holderWallet = VerifiableCredentialService.createWallet();

  const vc = new VCBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiableCredential'])
    .issuer(issuerWallet.did)
    .validFrom(new Date().toISOString())
    .credentialSubject({ id: holderWallet.did })
    .build();

  const signedVC = service.sign(vc.toJSON(), issuerWallet.privateKey);

  // Build VP without explicitly setting VerifiablePresentation type
  const vp = new VPBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['CustomPresentation']) // Only custom type
    .holder(holderWallet.did)
    .addCredential(signedVC)
    .build();

  // VerifiablePresentation should be auto-added
  assert.ok(vp.getType().includes('VerifiablePresentation'));
  assert.ok(vp.getType().includes('CustomPresentation'));
});

test('VP - End-to-end workflow', () => {
  const service = new VerifiableCredentialService();
  
  // University issues degree credential
  const universityWallet = VerifiableCredentialService.createWallet();
  const studentWallet = VerifiableCredentialService.createWallet();
  
  const degreeVC = new VCBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiableCredential', 'UniversityDegreeCredential'])
    .id('http://university.edu/credentials/degree/123')
    .issuer(universityWallet.did)
    .validFrom('2020-01-01T00:00:00Z')
    .credentialSubject({
      id: studentWallet.did,
      degree: 'Bachelor of Science',
      university: 'Example University'
    })
    .build();
  
  const signedDegreeVC = service.sign(degreeVC.toJSON(), universityWallet.privateKey);
  
  // Company issues employment credential
  const companyWallet = VerifiableCredentialService.createWallet();
  
  const employmentVC = new VCBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiableCredential', 'EmploymentCredential'])
    .id('http://company.com/credentials/employment/456')
    .issuer(companyWallet.did)
    .validFrom('2021-06-01T00:00:00Z')
    .credentialSubject({
      id: studentWallet.did,
      position: 'Software Engineer',
      company: 'Tech Corp'
    })
    .build();
  
  const signedEmploymentVC = service.sign(employmentVC.toJSON(), companyWallet.privateKey);
  
  // Student creates presentation for job application
  const presentation = new VPBuilder()
    .context(['https://www.w3.org/ns/credentials/v2'])
    .type(['VerifiablePresentation'])
    .id('http://student.example/presentations/job-application')
    .holder(studentWallet.did)
    .verifiableCredential([signedDegreeVC, signedEmploymentVC])
    .build();
  
  const signedPresentation = service.signPresentation(presentation.toJSON(), studentWallet.privateKey);
  
  // Verifier validates the presentation
  const vpValid = service.verifyPresentation(signedPresentation, studentWallet.publicKey);
  assert.strictEqual(vpValid, true, 'Presentation should be valid');
  
  // Verifier validates individual credentials
  const degreeValid = service.verify(signedPresentation.verifiableCredential[0], universityWallet.publicKey);
  const employmentValid = service.verify(signedPresentation.verifiableCredential[1], companyWallet.publicKey);
  
  assert.strictEqual(degreeValid, true, 'Degree credential should be valid');
  assert.strictEqual(employmentValid, true, 'Employment credential should be valid');
  
  // Verify holder matches
  assert.strictEqual(signedPresentation.holder, studentWallet.did);
});
