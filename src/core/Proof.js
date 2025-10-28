/**
 * Represents a Linked Data Proof according to the LD-Proofs specification.
 * https://w3c-ccg.github.io/ld-proofs/
 */
class Proof {
  constructor(type, created, verificationMethod, proofPurpose, proofValue) {
    this.type = type || null;
    this.created = created || null;
    this.verificationMethod = verificationMethod || null;
    this.proofPurpose = proofPurpose || null;
    this.proofValue = proofValue || null; // Changed from jws to proofValue per EcdsaSecp256r1Signature2019 spec
  }

  // Getters and Setters
  getType() {
    return this.type;
  }

  setType(type) {
    this.type = type;
    return this;
  }

  getCreated() {
    return this.created;
  }

  setCreated(created) {
    this.created = created;
    return this;
  }

  getVerificationMethod() {
    return this.verificationMethod;
  }

  setVerificationMethod(verificationMethod) {
    this.verificationMethod = verificationMethod;
    return this;
  }

  getProofPurpose() {
    return this.proofPurpose;
  }

  setProofPurpose(proofPurpose) {
    this.proofPurpose = proofPurpose;
    return this;
  }

  getProofValue() {
    return this.proofValue;
  }

  setProofValue(proofValue) {
    this.proofValue = proofValue;
    return this;
  }

  toJSON() {
    const result = {};
    if (this.type) result.type = this.type;
    if (this.created) result.created = this.created;
    if (this.verificationMethod) result.verificationMethod = this.verificationMethod;
    if (this.proofPurpose) result.proofPurpose = this.proofPurpose;
    if (this.proofValue) result.proofValue = this.proofValue; // Changed from jws to proofValue
    return result;
  }

  toString() {
    return `Proof{type='${this.type}', created='${this.created}', verificationMethod='${this.verificationMethod}', proofPurpose='${this.proofPurpose}', proofValue='${this.proofValue}'}`; // Changed from jws to proofValue
  }
}

export default Proof;