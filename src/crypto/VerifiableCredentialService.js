import crypto from 'crypto';
import JSONLDCanon from './JSONLDCanon.js';
import ProofGenerator from './ProofGenerator.js';

/**
 * FIPS-friendly Verifiable Credential Service
 * Uses Node crypto primitives with ECDSA P-256 and OpenSSL FIPS.
 */
class VerifiableCredentialService {
  static SIGNATURE_ALGORITHM = 'sha256'; // ECDSA P-256 uses SHA-256 digest
  static PROOF_TYPE = "EcdsaSecp256r1Signature2019";
  static PROOF_PURPOSE = "assertionMethod";
  static EC_CURVE_NAME = "P-256"; // Default to P-256 (secp256r1)

  /**
   * Signs a VC using ECDSA P-256 (FIPS mode).
   * @param {Object} vc - Verifiable Credential
   * @param {crypto.KeyObject|string} privateKey - Node crypto KeyObject or Base64 encoded private key
   * @returns {Object} VC with proof
   */
  sign(vc, privateKey) {
    const signedVc = JSON.parse(JSON.stringify(vc));

    // Prepare proof
    const proof = ProofGenerator.createProofWithMetadata(
      VerifiableCredentialService.PROOF_TYPE,
      VerifiableCredentialService.PROOF_PURPOSE,
      "did:example:123#key-1"
    );

    // Canonicalize VC (without proof)
    const canonicalVc = JSONLDCanon.canonicalize(vc, true);

    // Handle Base64 encoded private key
    const keyObject = this._getKeyObject(privateKey, 'private');

    // FIPS-compliant signing
    const sign = crypto.createSign(VerifiableCredentialService.SIGNATURE_ALGORITHM);
    sign.update(canonicalVc);
    sign.end();
    const signature = sign.sign(keyObject, 'base64');

    console.log("[FIPS AUDIT] Signed VC digest with ECDSA P-256");
    proof.setProofValue(signature); // Changed from setJws to setProofValue

    signedVc.proof = proof.toJSON();
    return signedVc;
  }

  /**
   * Verifies a VC using ECDSA P-256 (FIPS mode).
   * @param {Object} vc - Verifiable Credential
   * @param {crypto.KeyObject|string} publicKey - Node crypto KeyObject or Base64 encoded public key
   * @returns {boolean} true if valid
   */
  verify(vc, publicKey) {
    if (!vc.proof || !vc.proof.proofValue) return false; // Changed from jws to proofValue

    const proof = vc.proof;
    const signature = proof.proofValue; // Changed from jws to proofValue

    // Remove proof for canonicalization
    const vcWithoutProof = JSON.parse(JSON.stringify(vc));
    delete vcWithoutProof.proof;

    const canonicalVc = JSONLDCanon.canonicalize(vcWithoutProof);

    // Handle Base64 encoded public key
    const keyObject = this._getKeyObject(publicKey, 'public');

    // FIPS-compliant verification
    const verify = crypto.createVerify(VerifiableCredentialService.SIGNATURE_ALGORITHM);
    verify.update(canonicalVc);
    verify.end();

    const valid = verify.verify(keyObject, signature, 'base64');
    console.log(`[FIPS AUDIT] Verified VC signature: ${valid}`);
    return valid;
  }

  /**
   * Signs a VP (Verifiable Presentation) using ECDSA P-256 (FIPS mode).
   * @param {Object} vp - Verifiable Presentation
   * @param {crypto.KeyObject|string} privateKey - Node crypto KeyObject or Base64 encoded private key
   * @returns {Object} VP with proof
   */
  signPresentation(vp, privateKey) {
    const signedVp = JSON.parse(JSON.stringify(vp));

    // Prepare proof
    const proof = ProofGenerator.createProofWithMetadata(
      VerifiableCredentialService.PROOF_TYPE,
      "authentication", // VP uses authentication proof purpose
      vp.holder ? `${vp.holder}#key-1` : "did:example:holder#key-1"
    );

    // Canonicalize VP (without proof)
    const canonicalVp = JSONLDCanon.canonicalize(vp, true);

    // Handle Base64 encoded private key
    const keyObject = this._getKeyObject(privateKey, 'private');

    // FIPS-compliant signing
    const sign = crypto.createSign(VerifiableCredentialService.SIGNATURE_ALGORITHM);
    sign.update(canonicalVp);
    sign.end();
    const signature = sign.sign(keyObject, 'base64');

    console.log("[FIPS AUDIT] Signed VP digest with ECDSA P-256");
    proof.setProofValue(signature);

    signedVp.proof = proof.toJSON();
    return signedVp;
  }

  /**
   * Verifies a VP (Verifiable Presentation) using ECDSA P-256 (FIPS mode).
   * @param {Object} vp - Verifiable Presentation
   * @param {crypto.KeyObject|string} publicKey - Node crypto KeyObject or Base64 encoded public key
   * @returns {boolean} true if valid
   */
  verifyPresentation(vp, publicKey) {
    if (!vp.proof || !vp.proof.proofValue) return false;

    const proof = vp.proof;
    const signature = proof.proofValue;

    // Remove proof for canonicalization
    const vpWithoutProof = JSON.parse(JSON.stringify(vp));
    delete vpWithoutProof.proof;

    const canonicalVp = JSONLDCanon.canonicalize(vpWithoutProof);

    // Handle Base64 encoded public key
    const keyObject = this._getKeyObject(publicKey, 'public');

    // FIPS-compliant verification
    const verify = crypto.createVerify(VerifiableCredentialService.SIGNATURE_ALGORITHM);
    verify.update(canonicalVp);
    verify.end();

    const valid = verify.verify(keyObject, signature, 'base64');
    console.log(`[FIPS AUDIT] Verified VP signature: ${valid}`);
    return valid;
  }

  /**
   * Helper method to convert Base64 string to KeyObject if needed
   * @param {crypto.KeyObject|string} key - KeyObject or Base64 encoded key
   * @param {string} type - 'private' or 'public'
   * @returns {crypto.KeyObject} KeyObject
   * @private
   */
  _getKeyObject(key, type) {
    if (typeof key === 'string') {
      // Convert Base64 encoded key to KeyObject
      const keyBuffer = Buffer.from(key, 'base64');
      if (type === 'private') {
        return crypto.createPrivateKey({
          key: keyBuffer,
          format: 'der',
          type: 'pkcs8'
        });
      } else {
        return crypto.createPublicKey({
          key: keyBuffer,
          format: 'der',
          type: 'spki'
        });
      }
    }
    // Already a KeyObject
    return key;
  }

  /**
   * Helper method to generate a new EC key pair
   * @returns {Object} Object containing Base64 encoded publicKey and privateKey
   */
  static generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: VerifiableCredentialService.EC_CURVE_NAME
    });

    // Export keys as Base64 DER format
    const publicKeyBase64 = publicKey.export({
      format: 'der',
      type: 'spki'
    }).toString('base64');

    const privateKeyBase64 = privateKey.export({
      format: 'der',
      type: 'pkcs8'
    }).toString('base64');

    return {
      publicKey: publicKeyBase64,
      privateKey: privateKeyBase64
    };
  }

  /**
   * Helper method to create a wallet with a new key pair
   * @returns {Object} Wallet object with DID and Base64 encoded keys
   */
  static createWallet() {
    const { publicKey, privateKey } = this.generateKeyPair();
    return {
      did: `did:example:${crypto.randomUUID()}`,
      publicKey: publicKey,
      privateKey: privateKey
    };
  }
}

export default VerifiableCredentialService;