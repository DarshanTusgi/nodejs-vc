import VerifiablePresentation from '../core/VerifiablePresentation.js';

/**
 * Builder class for constructing Verifiable Presentations.
 * Provides a fluent API for constructing VPs with all required fields.
 */
class VPBuilder {
  constructor() {
    this.vp = new VerifiablePresentation();
    this.vp.setContext(['https://www.w3.org/ns/credentials/v2']);  // v2.0 context
    this.vp.setType([]);
    this.vp.setVerifiableCredential([]);
  }

  /**
   * Sets the @context of the Verifiable Presentation.
   * 
   * @param {Array} context The context URIs
   * @returns {VPBuilder} The builder instance
   */
  context(context) {
    this.vp.setContext(context);
    return this;
  }

  /**
   * Adds a context to the Verifiable Presentation.
   * 
   * @param {string} context The context URI to add
   * @returns {VPBuilder} The builder instance
   */
  addContext(context) {
    this.vp.getContext().push(context);
    return this;
  }

  /**
   * Sets the type of the Verifiable Presentation.
   * 
   * @param {Array} type The type URIs
   * @returns {VPBuilder} The builder instance
   */
  type(type) {
    this.vp.setType(type);
    return this;
  }

  /**
   * Adds a type to the Verifiable Presentation.
   * 
   * @param {string} type The type URI to add
   * @returns {VPBuilder} The builder instance
   */
  addType(type) {
    this.vp.getType().push(type);
    return this;
  }

  /**
   * Sets the ID of the Verifiable Presentation.
   * 
   * @param {string} id The presentation ID
   * @returns {VPBuilder} The builder instance
   */
  id(id) {
    this.vp.setId(id);
    return this;
  }

  /**
   * Sets the holder of the Verifiable Presentation.
   * 
   * @param {string} holder The holder DID
   * @returns {VPBuilder} The builder instance
   */
  holder(holder) {
    this.vp.setHolder(holder);
    return this;
  }

  /**
   * Sets the verifiable credentials array.
   * 
   * @param {Array} credentials Array of verifiable credentials
   * @returns {VPBuilder} The builder instance
   */
  verifiableCredential(credentials) {
    this.vp.setVerifiableCredential(credentials);
    return this;
  }

  /**
   * Adds a single verifiable credential to the presentation.
   * 
   * @param {Object} credential The verifiable credential to add
   * @returns {VPBuilder} The builder instance
   */
  addCredential(credential) {
    this.vp.addVerifiableCredential(credential);
    return this;
  }

  /**
   * Validates and builds the Verifiable Presentation.
   * 
   * @returns {VerifiablePresentation} The constructed VP
   * @throws {Error} If required fields are missing
   */
  build() {
    // Validate required fields
    if (!this.vp.getHolder()) {
      throw new Error('Holder is required');
    }

    if (!this.vp.getVerifiableCredential() || this.vp.getVerifiableCredential().length === 0) {
      throw new Error('At least one verifiable credential is required');
    }

    // Ensure type includes VerifiablePresentation
    if (!this.vp.getType().includes('VerifiablePresentation')) {
      this.vp.addType('VerifiablePresentation');
    }

    return this.vp;
  }
}

export default VPBuilder;
