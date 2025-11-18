/**
 * Represents a W3C Verifiable Credential according to the specification.
 * https://www.w3.org/TR/vc-data-model/
 */
class VerifiableCredential {
  constructor(context, type, id, issuer, validFrom, validUntil, credentialSubject, proof) {
    this['@context'] = context || [];
    this.type = type || [];
    this.id = id || null;
    this.issuer = issuer || null;
    this.validFrom = validFrom || null;  // Changed from issuanceDate to validFrom for v2.0
    this.validUntil = validUntil || null;  // Changed from expirationDate to validUntil for v2.0
    this.credentialSubject = credentialSubject || null;
    this.proof = proof || null;
  }

  // Getters and Setters
  getContext() {
    return this['@context'];
  }

  setContext(context) {
    this['@context'] = context;
    return this;
  }

  getType() {
    return this.type;
  }

  setType(type) {
    this.type = type;
    return this;
  }

  getId() {
    return this.id;
  }

  setId(id) {
    this.id = id;
    return this;
  }

  getIssuer() {
    return this.issuer;
  }

  setIssuer(issuer) {
    this.issuer = issuer;
    return this;
  }

  getValidFrom() {
    return this.validFrom;
  }

  setValidFrom(validFrom) {
    this.validFrom = validFrom;
    return this;
  }

  getValidUntil() {
    return this.validUntil;
  }

  setValidUntil(validUntil) {
    this.validUntil = validUntil;
    return this;
  }

  // Deprecated v1.0 methods for backward compatibility
  getIssuanceDate() {
    return this.validFrom;
  }

  setIssuanceDate(issuanceDate) {
    this.validFrom = issuanceDate;
    return this;
  }

  getExpirationDate() {
    return this.validUntil;
  }

  setExpirationDate(expirationDate) {
    this.validUntil = expirationDate;
    return this;
  }

  getCredentialSubject() {
    return this.credentialSubject;
  }

  setCredentialSubject(credentialSubject) {
    this.credentialSubject = credentialSubject;
    return this;
  }

  getProof() {
    return this.proof;
  }

  setProof(proof) {
    this.proof = proof;
    return this;
  }

  toJSON() {
    const result = {};
    if (this['@context']) result['@context'] = this['@context'];
    if (this.type) result.type = this.type;
    if (this.id) result.id = this.id;
    if (this.issuer) result.issuer = this.issuer;
    if (this.validFrom) result.validFrom = this.validFrom;  // Changed from issuanceDate to validFrom for v2.0
    if (this.validUntil) result.validUntil = this.validUntil;  // Changed from expirationDate to validUntil for v2.0
    if (this.credentialSubject) result.credentialSubject = this.credentialSubject;
    if (this.proof) result.proof = this.proof;
    return result;
  }

  toString() {
    return `VerifiableCredential{context=${JSON.stringify(this['@context'])}, type=${JSON.stringify(this.type)}, id='${this.id}', issuer='${this.issuer}', validFrom='${this.validFrom}', validUntil='${this.validUntil}', credentialSubject=${JSON.stringify(this.credentialSubject)}, proof=${JSON.stringify(this.proof)}}`;
  }
}

export default VerifiableCredential;