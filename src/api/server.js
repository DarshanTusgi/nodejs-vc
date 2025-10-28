import express from 'express';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import { VerifiableCredentialService } from '../crypto/index.js';
import { VCBuilder } from '../builder/index.js';

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Swagger definition
const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Verifiable Credentials API',
      version: '1.0.0',
      description: 'API for signing, verifying, and generating key pairs for W3C Verifiable Credentials',
    },
    servers: [
      {
        url: `http://localhost:${port}`,
        description: 'Development server',
      },
    ],
  },
  apis: ['./src/api/server.js'], // files containing annotations as above
};

const specs = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

/**
 * @swagger
 * components:
 *   schemas:
 *     Keypair:
 *       type: object
 *       properties:
 *         publicKey:
 *           type: string
 *           description: Base64 encoded public key
 *           example: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwaXN2oYihGe28Uo5TWn2KG4EnnnaYLIDrcNF9d5E3/qr390XBBMT2IWZqvTmG06ugAhbxjKXfYmRY40igOK8sg=="
 *         privateKey:
 *           type: string
 *           description: Base64 encoded private key
 *           example: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUOb4FFfSpDDT5jKcfU3y90L3Ifc7Ui9soOpJgdyhGsmhRANCAATBpc3ahiKEZ7bxSjlNafYobgSeedpgsgOtw0X13kTf+qvf3RcEExPYhZmq9OYbTq6ACFvGMpd9iZFjjSKA4ryy"
 *     Credential:
 *       type: object
 *       required:
 *         - '@context'
 *         - type
 *         - issuer
 *         - issuanceDate
 *         - credentialSubject
 *       properties:
 *         '@context':
 *           type: array
 *           items:
 *             type: string
 *           description: The JSON-LD context(s) of the credential
 *           example: ["https://www.w3.org/2018/credentials/v1"]
 *         type:
 *           type: array
 *           items:
 *             type: string
 *           description: The type(s) of the credential
 *           example: ["VerifiableCredential"]
 *         id:
 *           type: string
 *           description: The unique identifier of the credential
 *           example: "http://example.edu/credentials/123"
 *         issuer:
 *           type: string
 *           description: The issuer of the credential (DID or URL)
 *           example: "did:example:123456789abcdefghi"
 *         issuanceDate:
 *           type: string
 *           format: date-time
 *           description: The issuance date of the credential
 *           example: "2023-06-01T12:00:00Z"
 *         expirationDate:
 *           type: string
 *           format: date-time
 *           description: The expiration date of the credential (optional)
 *           example: "2024-06-01T12:00:00Z"
 *         credentialSubject:
 *           type: object
 *           description: The subject of the credential
 *           example:
 *             id: "did:example:ebfeb1f712ebc6f1c276e12ec21"
 *             name: "Jane Doe"
 *             degree: "Bachelor of Science and Arts"
 *     SignedCredential:
 *       allOf:
 *         - $ref: '#/components/schemas/Credential'
 *         - type: object
 *           properties:
 *             proof:
 *               type: object
 *               description: The proof object containing the signature
 *               properties:
 *                 type:
 *                   type: string
 *                   example: "EcdsaSecp256r1Signature2019"
 *                 created:
 *                   type: string
 *                   format: date-time
 *                   example: "2023-06-01T12:05:00Z"
 *                 verificationMethod:
 *                   type: string
 *                   example: "did:example:123#key-1"
 *                 proofPurpose:
 *                   type: string
 *                   example: "assertionMethod"
 *                 proofValue:
 *                   type: string
 *                   example: "MEUCIQDmWRxEbizYf32G1ZVxbNyv/NL8kOG353a7QnEMCFqDKgIgXEOawS1DetQo+GKaCJuNKrlwSQBR47nKGRTyaG9lRmA="
 *     SignRequest:
 *       type: object
 *       required:
 *         - credential
 *         - privateKey
 *       properties:
 *         credential:
 *           $ref: '#/components/schemas/Credential'
 *         privateKey:
 *           type: string
 *           description: Base64 encoded private key for signing
 *           example: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUOb4FFfSpDDT5jKcfU3y90L3Ifc7Ui9soOpJgdyhGsmhRANCAATBpc3ahiKEZ7bxSjlNafYobgSeedpgsgOtw0X13kTf+qvf3RcEExPYhZmq9OYbTq6ACFvGMpd9iZFjjSKA4ryy"
 *     SignResponse:
 *       type: object
 *       properties:
 *         signedCredential:
 *           $ref: '#/components/schemas/SignedCredential'
 *     VerifyRequest:
 *       type: object
 *       required:
 *         - credential
 *         - publicKey
 *       properties:
 *         credential:
 *           $ref: '#/components/schemas/SignedCredential'
 *         publicKey:
 *           type: string
 *           description: Base64 encoded public key for verification
 *           example: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwaXN2oYihGe28Uo5TWn2KG4EnnnaYLIDrcNF9d5E3/qr390XBBMT2IWZqvTmG06ugAhbxjKXfYmRY40igOK8sg=="
 *     VerifyResponse:
 *       type: object
 *       properties:
 *         valid:
 *           type: boolean
 *           description: Whether the credential signature is valid
 *           example: true
 */

/**
 * @swagger
 * /api/keypair:
 *   get:
 *     summary: Generate a new key pair
 *     description: Generates a new ECDSA P-256 key pair for signing and verifying credentials
 *     responses:
 *       200:
 *         description: A key pair object
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Keypair'
 *             example:
 *               publicKey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwaXN2oYihGe28Uo5TWn2KG4EnnnaYLIDrcNF9d5E3/qr390XBBMT2IWZqvTmG06ugAhbxjKXfYmRY40igOK8sg=="
 *               privateKey: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUOb4FFfSpDDT5jKcfU3y90L3Ifc7Ui9soOpJgdyhGsmhRANCAATBpc3ahiKEZ7bxSjlNafYobgSeedpgsgOtw0X13kTf+qvf3RcEExPYhZmq9OYbTq6ACFvGMpd9iZFjjSKA4ryy"
 */
app.get('/api/keypair', (req, res) => {
  try {
    const keyPair = VerifiableCredentialService.generateKeyPair();
    res.json(keyPair);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/sign:
 *   post:
 *     summary: Sign a verifiable credential
 *     description: Signs a verifiable credential with the provided private key
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/SignRequest'
 *           example:
 *             credential:
 *               '@context':
 *                 - "https://www.w3.org/2018/credentials/v1"
 *               type:
 *                 - "VerifiableCredential"
 *               id: "http://example.edu/credentials/123"
 *               issuer: "did:example:123456789abcdefghi"
 *               issuanceDate: "2023-06-01T12:00:00Z"
 *               credentialSubject:
 *                 id: "did:example:ebfeb1f712ebc6f1c276e12ec21"
 *                 name: "Jane Doe"
 *                 degree: "Bachelor of Science and Arts"
 *             privateKey: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUOb4FFfSpDDT5jKcfU3y90L3Ifc7Ui9soOpJgdyhGsmhRANCAATBpc3ahiKEZ7bxSjlNafYobgSeedpgsgOtw0X13kTf+qvf3RcEExPYhZmq9OYbTq6ACFvGMpd9iZFjjSKA4ryy"
 *     responses:
 *       200:
 *         description: A signed verifiable credential
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SignResponse'
 *             example:
 *               signedCredential:
 *                 '@context':
 *                   - "https://www.w3.org/2018/credentials/v1"
 *                 type:
 *                   - "VerifiableCredential"
 *                 id: "http://example.edu/credentials/123"
 *                 issuer: "did:example:123456789abcdefghi"
 *                 issuanceDate: "2023-06-01T12:00:00Z"
 *                 credentialSubject:
 *                   id: "did:example:ebfeb1f712ebc6f1c276e12ec21"
 *                   name: "Jane Doe"
 *                   degree: "Bachelor of Science and Arts"
 *                 proof:
 *                   type: "EcdsaSecp256r1Signature2019"
 *                   created: "2023-06-01T12:05:00Z"
 *                   verificationMethod: "did:example:123#key-1"
 *                   proofPurpose: "assertionMethod"
 *                   proofValue: "MEUCIQDmWRxEbizYf32G1ZVxbNyv/NL8kOG353a7QnEMCFqDKgIgXEOawS1DetQo+GKaCJuNKrlwSQBR47nKGRTyaG9lRmA="
 *       400:
 *         description: Invalid request
 *       500:
 *         description: Internal server error
 */
app.post('/api/sign', (req, res) => {
  try {
    const { credential, privateKey } = req.body;
    
    if (!credential || !privateKey) {
      return res.status(400).json({ error: 'Credential and privateKey are required' });
    }
    
    // Create VC from the provided credential object
    const vc = new VCBuilder()
      .context(credential['@context'] || ['https://www.w3.org/2018/credentials/v1'])
      .type(credential.type || ['VerifiableCredential'])
      .id(credential.id || `http://example.edu/credentials/${Date.now()}`)
      .issuer(credential.issuer || 'did:example:issuer')
      .issuanceDate(credential.issuanceDate || new Date().toISOString())
      .credentialSubject(credential.credentialSubject || {});
    
    // Add optional fields if they exist
    if (credential.expirationDate) {
      vc.expirationDate(credential.expirationDate);
    }
    
    const builtVc = vc.build();
    
    // Sign the VC
    const service = new VerifiableCredentialService();
    const signedVc = service.sign(builtVc, privateKey);
    
    res.json({ signedCredential: signedVc });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/verify:
 *   post:
 *     summary: Verify a signed verifiable credential
 *     description: Verifies the signature of a signed verifiable credential with the provided public key
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/VerifyRequest'
 *           example:
 *             credential:
 *               '@context':
 *                 - "https://www.w3.org/2018/credentials/v1"
 *               type:
 *                 - "VerifiableCredential"
 *               id: "http://example.edu/credentials/123"
 *               issuer: "did:example:123456789abcdefghi"
 *               issuanceDate: "2023-06-01T12:00:00Z"
 *               credentialSubject:
 *                 id: "did:example:ebfeb1f712ebc6f1c276e12ec21"
 *                 name: "Jane Doe"
 *                 degree: "Bachelor of Science and Arts"
 *               proof:
 *                 type: "EcdsaSecp256r1Signature2019"
 *                 created: "2023-06-01T12:05:00Z"
 *                 verificationMethod: "did:example:123#key-1"
 *                 proofPurpose: "assertionMethod"
 *                 proofValue: "MEUCIQDmWRxEbizYf32G1ZVxbNyv/NL8kOG353a7QnEMCFqDKgIgXEOawS1DetQo+GKaCJuNKrlwSQBR47nKGRTyaG9lRmA="
 *             publicKey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwaXN2oYihGe28Uo5TWn2KG4EnnnaYLIDrcNF9d5E3/qr390XBBMT2IWZqvTmG06ugAhbxjKXfYmRY40igOK8sg=="
 *     responses:
 *       200:
 *         description: Verification result
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/VerifyResponse'
 *             example:
 *               valid: true
 *       400:
 *         description: Invalid request
 *       500:
 *         description: Internal server error
 */
app.post('/api/verify', (req, res) => {
  try {
    const { credential, publicKey } = req.body;
    
    if (!credential || !publicKey) {
      return res.status(400).json({ error: 'Credential and publicKey are required' });
    }
    
    // Verify the VC
    const service = new VerifiableCredentialService();
    const isValid = service.verify(credential, publicKey);
    
    res.json({ valid: isValid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
app.listen(port, () => {
  console.log('Verifiable Credentials API server running on port ' + port);
  console.log('Swagger UI available at http://localhost:' + port + '/api-docs');
});

export default app;