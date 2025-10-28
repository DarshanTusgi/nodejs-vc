/**
 * Utility class for handling key formats (JWK, Base58, Base64).
 */
class KeyUtils {
  /**
   * Encodes a public key in Base64 format.
   * 
   * @param {Buffer} publicKey The public key to encode
   * @returns {string} Base64 encoded public key
   */
  static encodePublicKeyBase64(publicKey) {
    return publicKey.toString('base64');
  }

  /**
   * Decodes a Base64 encoded public key.
   * 
   * @param {string} encodedKey The Base64 encoded public key
   * @returns {Buffer} The decoded public key
   */
  static decodePublicKeyBase64(encodedKey) {
    return Buffer.from(encodedKey, 'base64');
  }

  /**
   * Encodes a private key in Base64 format.
   * 
   * @param {Buffer} privateKey The private key to encode
   * @returns {string} Base64 encoded private key
   */
  static encodePrivateKeyBase64(privateKey) {
    return privateKey.toString('base64');
  }

  /**
   * Decodes a Base64 encoded private key.
   * 
   * @param {string} encodedKey The Base64 encoded private key
   * @returns {Buffer} The decoded private key
   */
  static decodePrivateKeyBase64(encodedKey) {
    return Buffer.from(encodedKey, 'base64');
  }

  /**
   * Converts a public key to JWK format.
   * 
   * @param {Buffer} publicKey The public key to convert
   * @param {string} algorithm The key algorithm (e.g., "ES256")
   * @returns {object} JWK representation of the public key
   */
  static toJwk(publicKey, algorithm) {
    // This is a simplified implementation
    // In a real implementation, you would create a proper JWK
    return {
      kty: 'EC',
      crv: 'P-256',
      x: publicKey.toString('base64'),
      alg: algorithm
    };
  }

  /**
   * Converts a JWK to a public key.
   * 
   * @param {object} jwk The JWK representation
   * @returns {Buffer} The public key
   */
  static fromJwk(jwk) {
    // This is a simplified implementation
    // In a real implementation, you would parse the JWK properly
    return Buffer.from(jwk.x, 'base64');
  }
}

export default KeyUtils;