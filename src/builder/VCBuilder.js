import { VerifiableCredential } from '../core/index.js';

/**
 * Builder class for creating Verifiable Credentials.
 * Provides a fluent API for constructing VCs with all required fields.
 */
class VCBuilder {
  constructor() {
    this.vc = new VerifiableCredential();
    this.vc.setContext(['https://www.w3.org/ns/credentials/v2']);  // Updated to v2.0 context
    this.vc.setType([]);
  }

  /**
   * Sets the @context of the Verifiable Credential.
   * 
   * @param {Array} context The context URIs
   * @returns {VCBuilder} The builder instance
   */
  context(context) {
    this.vc.setContext(context);
    return this;
  }

  /**
   * Adds a context to the Verifiable Credential.
   * 
   * @param {string} context The context URI to add
   * @returns {VCBuilder} The builder instance
   */
  addContext(context) {
    this.vc.getContext().push(context);
    return this;
  }

  /**
   * Sets the type of the Verifiable Credential.
   * 
   * @param {Array} type The type URIs
   * @returns {VCBuilder} The builder instance
   */
  type(type) {
    this.vc.setType(type);
    return this;
  }

  /**
   * Adds a type to the Verifiable Credential.
   * 
   * @param {string} type The type URI to add
   * @returns {VCBuilder} The builder instance
   */
  addType(type) {
    this.vc.getType().push(type);
    return this;
  }

  /**
   * Sets the ID of the Verifiable Credential.
   * 
   * @param {string} id The credential ID
   * @returns {VCBuilder} The builder instance
   */
  id(id) {
    this.vc.setId(id);
    return this;
  }

  /**
   * Sets the issuer of the Verifiable Credential.
   * 
   * @param {string} issuer The issuer DID or URI
   * @returns {VCBuilder} The builder instance
   */
  issuer(issuer) {
    this.vc.setIssuer(issuer);
    return this;
  }

  /**
   * Sets the valid from date of the Verifiable Credential.
   * 
   * @param {string} validFrom The valid from date in ISO 8601 format
   * @returns {VCBuilder} The builder instance
   */
  validFrom(validFrom) {
    this.vc.setValidFrom(validFrom);
    return this;
  }

  /**
   * Sets the valid until date of the Verifiable Credential.
   * 
   * @param {string} validUntil The valid until date in ISO 8601 format
   * @returns {VCBuilder} The builder instance
   */
  validUntil(validUntil) {
    this.vc.setValidUntil(validUntil);
    return this;
  }

  /**
   * Sets the issuance date of the Verifiable Credential (deprecated v1.0 method).
   * 
   * @param {string} issuanceDate The issuance date in ISO 8601 format
   * @returns {VCBuilder} The builder instance
   */
  issuanceDate(issuanceDate) {
    this.vc.setIssuanceDate(issuanceDate);
    return this;
  }

  /**
   * Sets the expiration date of the Verifiable Credential (deprecated v1.0 method).
   * 
   * @param {string} expirationDate The expiration date in ISO 8601 format
   * @returns {VCBuilder} The builder instance
   */
  expirationDate(expirationDate) {
    this.vc.setExpirationDate(expirationDate);
    return this;
  }

  /**
   * Sets the credential subject of the Verifiable Credential.
   * 
   * @param {object} credentialSubject The credential subject
   * @returns {VCBuilder} The builder instance
   */
  credentialSubject(credentialSubject) {
    this.vc.setCredentialSubject(credentialSubject);
    return this;
  }

  /**
   * Builds the Verifiable Credential.
   * 
   * @returns {VerifiableCredential} The constructed VerifiableCredential
   */
  build() {
    // Validate required fields
    if (!this.vc.getContext() || this.vc.getContext().length === 0) {
      throw new Error("Verifiable Credential must have at least one context");
    }

    if (!this.vc.getType() || this.vc.getType().length === 0) {
      throw new Error("Verifiable Credential must have at least one type");
    }

    if (!this.vc.getIssuer()) {
      throw new Error("Verifiable Credential must have an issuer");
    }

    if (!this.vc.getValidFrom()) {
      throw new Error("Verifiable Credential must have a valid from date");
    }

    if (!this.vc.getCredentialSubject()) {
      throw new Error("Verifiable Credential must have a credential subject");
    }

    return this.vc;
  }
}

export default VCBuilder;