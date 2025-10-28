/**
 * Represents a W3C Verifiable Credential according to the specification.
 * https://www.w3.org/TR/vc-data-model/
 */
class VerifiableCredential {
  constructor(context, type, id, issuer, issuanceDate, expirationDate, credentialSubject, proof) {
    this['@context'] = context || [];
    this.type = type || [];
    this.id = id || null;
    this.issuer = issuer || null;
    this.issuanceDate = issuanceDate || null;
    this.expirationDate = expirationDate || null;
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

  getIssuanceDate() {
    return this.issuanceDate;
  }

  setIssuanceDate(issuanceDate) {
    this.issuanceDate = issuanceDate;
    return this;
  }

  getExpirationDate() {
    return this.expirationDate;
  }

  setExpirationDate(expirationDate) {
    this.expirationDate = expirationDate;
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
    if (this.issuanceDate) result.issuanceDate = this.issuanceDate;
    if (this.expirationDate) result.expirationDate = this.expirationDate;
    if (this.credentialSubject) result.credentialSubject = this.credentialSubject;
    if (this.proof) result.proof = this.proof;
    return result;
  }

  toString() {
    return `VerifiableCredential{context=${JSON.stringify(this['@context'])}, type=${JSON.stringify(this.type)}, id='${this.id}', issuer='${this.issuer}', issuanceDate='${this.issuanceDate}', expirationDate='${this.expirationDate}', credentialSubject=${JSON.stringify(this.credentialSubject)}, proof=${JSON.stringify(this.proof)}}`;
  }
}

export default VerifiableCredential;