import canonicalize from 'canonicalize';

/**
 * Helper class for JSON-LD canonicalization of Verifiable Credentials.
 * Implements deterministic serialization for cryptographic operations.
 */
class JSONLDCanon {
  /**
   * Performs deterministic JSON-LD canonicalization of a Verifiable Credential.
   * 
   * @param {VerifiableCredential|object} vc The Verifiable Credential to canonicalize
   * @param {boolean} excludeProof Whether to exclude the proof field (default: false)
   * @returns {string} Canonicalized JSON string
   * 
   * VC Canonicalization: Deterministic JSON serialization with sorted keys
   */
  static canonicalize(vc, excludeProof = false) {
    try {
      // Convert VC to canonical JSON
      let obj = vc.toJSON ? vc.toJSON() : vc;
      
      // Exclude proof field if requested (for signing)
      if (excludeProof && obj.proof) {
        obj = JSON.parse(JSON.stringify(obj));
        delete obj.proof;
      }
      
      return canonicalize(obj);
    } catch (error) {
      throw new Error(`Failed to canonicalize Verifiable Credential: ${error.message}`);
    }
  }
}

export default JSONLDCanon;