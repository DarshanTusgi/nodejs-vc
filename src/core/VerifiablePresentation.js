/**
 * Represents a W3C Verifiable Presentation according to the v2.0 specification.
 * https://www.w3.org/TR/vc-data-model-2.0/
 */
class VerifiablePresentation {
  constructor(context, type, id, holder, verifiableCredential, proof) {
    this['@context'] = context || [];
    this.type = type || [];
    this.id = id || null;
    this.holder = holder || null;
    this.verifiableCredential = verifiableCredential || [];
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

  addType(type) {
    if (!Array.isArray(this.type)) {
      this.type = [];
    }
    this.type.push(type);
    return this;
  }

  getId() {
    return this.id;
  }

  setId(id) {
    this.id = id;
    return this;
  }

  getHolder() {
    return this.holder;
  }

  setHolder(holder) {
    this.holder = holder;
    return this;
  }

  getVerifiableCredential() {
    return this.verifiableCredential;
  }

  setVerifiableCredential(verifiableCredential) {
    this.verifiableCredential = verifiableCredential;
    return this;
  }

  addVerifiableCredential(credential) {
    if (!Array.isArray(this.verifiableCredential)) {
      this.verifiableCredential = [];
    }
    this.verifiableCredential.push(credential);
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
    if (this.holder) result.holder = this.holder;
    if (this.verifiableCredential) result.verifiableCredential = this.verifiableCredential;
    if (this.proof) result.proof = this.proof;
    return result;
  }

  toString() {
    return `VerifiablePresentation{context=${JSON.stringify(this['@context'])}, type=${JSON.stringify(this.type)}, id='${this.id}', holder='${this.holder}', verifiableCredential=${JSON.stringify(this.verifiableCredential)}, proof=${JSON.stringify(this.proof)}}`;
  }
}

export default VerifiablePresentation;
