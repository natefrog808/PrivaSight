/**
 * ZKPAccessVerifier
 * 
 * Implements Zero-Knowledge Proof generation and verification for the PrivaSight
 * privacy layer. This component handles the cryptographic proof mechanisms that
 * allow verifying access rights, computation integrity, and data ownership
 * without revealing sensitive information.
 */

const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto'); // For secure random number generation
const logger = require('../../utils/logger')('privacy-layer:zkp-verifier');

/**
 * Zero-Knowledge Proof Access Verifier
 * @class ZKPAccessVerifier
 */
class ZKPAccessVerifier {
  /**
   * Create a new ZKP Access Verifier
   * @param {Object} options - Configuration options
   * @param {Object} options.prover - ZKP prover instance
   * @param {Object} options.verifier - ZKP verifier instance
   * @param {Function} options.hashFunction - Hash function to use (must be cryptographically secure)
   * @param {Object} [options.config] - Additional configuration
   */
  constructor({ prover, verifier, hashFunction, config = {} }) {
    this.prover = prover;
    this.verifier = verifier;
    this.hashFunction = hashFunction;
    this.config = config;

    // Storage for proofs and verification keys
    this.proofs = new Map();
    this.verificationKeys = new Map();

    logger.info('ZKP Access Verifier initialized');
  }

  /**
   * Generate a zero-knowledge proof for data access
   * @param {Object} accessData - Data for access proof
   * @param {string} accessData.dataVaultId - ID of the data vault
   * @param {string} accessData.researcher - Address of the researcher
   * @param {number} accessData.accessType - Type of access (e.g., 0 for one-time, 1 for subscription)
   * @param {number} accessData.timestamp - Timestamp of the access request
   * @returns {Promise<Object>} Generated access proof
   */
  async generateAccessProof(accessData) {
    try {
      logger.info(`Generating access proof for vault ${accessData.dataVaultId} and researcher ${accessData.researcher}`);

      const proofId = uuidv4();

      const circuitInputs = {
        dataVaultId: BigInt(accessData.dataVaultId).toString(),
        researcherAddress: this.hashFunction(accessData.researcher),
        accessType: accessData.accessType,
        timestamp: accessData.timestamp,
        nonce: crypto.randomBytes(16).toString('hex') // Cryptographically secure nonce
      };

      const { proof, publicSignals } = await this.prover.generateProof('access', circuitInputs);

      const accessProof = {
        id: proofId,
        type: 'access',
        proof,
        publicSignals,
        proofData: this.serializeProof(proof, publicSignals), // For on-chain use
        metadata: {
          dataVaultId: accessData.dataVaultId,
          researcher: accessData.researcher,
          accessType: accessData.accessType,
          timestamp: accessData.timestamp,
          expiresAt: accessData.timestamp + (this.config.proofExpirationPeriod || 86400000) // Default: 24 hours
        },
        createdAt: Date.now()
      };

      this.proofs.set(proofId, accessProof);

      logger.info(`Access proof ${proofId} generated successfully`);
      return accessProof;
    } catch (error) {
      logger.error(`Failed to generate access proof:`, error);
      throw new Error(`Access proof generation failed: ${error.message}`);
    }
  }

  /**
   * Verify an access proof
   * @param {Object} proof - The access proof to verify
   * @returns {Promise<boolean>} Whether the proof is valid
   */
  async verifyAccessProof(proof) {
    try {
      logger.info(`Verifying access proof ${proof.id}`);

      const storedProof = this.proofs.get(proof.id);
      if (!storedProof || storedProof.type !== 'access') {
        logger.warn(`Access proof ${proof.id} not found or invalid type`);
        return false;
      }

      if (storedProof.metadata.expiresAt < Date.now()) {
        logger.warn(`Access proof ${proof.id} has expired`);
        return false;
      }

      const isValid = await this.verifier.verifyProof('access', proof.proof, proof.publicSignals);

      if (isValid) {
        logger.info(`Access proof ${proof.id} verified successfully`);
      } else {
        logger.warn(`Access proof ${proof.id} verification failed`);
      }

      return isValid;
    } catch (error) {
      logger.error(`Verification error for access proof ${proof.id}:`, error);
      return false;
    }
  }

  /**
   * Generate a zero-knowledge proof for computation integrity
   * @param {Object} computationData - Data for computation proof
   * @param {string} computationData.computationId - ID of the computation
   * @param {string} computationData.computationType - Type of computation
   * @param {Array<string>} computationData.dataVaultIds - IDs of data vaults used
   * @param {string} computationData.resultHash - Hash of the computation result
   * @returns {Promise<Object>} Generated computation proof
   */
  async generateComputationProof(computationData) {
    try {
      logger.info(`Generating computation proof for computation ${computationData.computationId}`);

      const proofId = uuidv4();

      const circuitInputs = {
        computationId: this.hashFunction(computationData.computationId),
        computationType: computationData.computationType,
        dataVaultIds: computationData.dataVaultIds.map(id => BigInt(id).toString()),
        resultHash: computationData.resultHash,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex') // Cryptographically secure nonce
      };

      const { proof, publicSignals } = await this.prover.generateProof('computation', circuitInputs);

      const computationProof = {
        id: proofId,
        type: 'computation',
        proof,
        publicSignals,
        proofData: this.serializeProof(proof, publicSignals), // For on-chain use
        metadata: {
          computationId: computationData.computationId,
          computationType: computationData.computationType,
          dataVaultIds: computationData.dataVaultIds,
          resultHash: computationData.resultHash,
          timestamp: Date.now()
        },
        createdAt: Date.now()
      };

      this.proofs.set(proofId, computationProof);

      logger.info(`Computation proof ${proofId} generated successfully`);
      return computationProof;
    } catch (error) {
      logger.error(`Failed to generate computation proof:`, error);
      throw new Error(`Computation proof generation failed: ${error.message}`);
    }
  }

  /**
   * Verify a computation proof
   * @param {Object} proof - The computation proof to verify
   * @returns {Promise<boolean>} Whether the proof is valid
   */
  async verifyComputationProof(proof) {
    try {
      logger.info(`Verifying computation proof ${proof.id}`);

      const isValid = await this.verifier.verifyProof('computation', proof.proof, proof.publicSignals);

      if (isValid) {
        logger.info(`Computation proof ${proof.id} verified successfully`);
      } else {
        logger.warn(`Computation proof ${proof.id} verification failed`);
      }

      return isValid;
    } catch (error) {
      logger.error(`Verification error for computation proof ${proof.id}:`, error);
      return false;
    }
  }

  /**
   * Generate a zero-knowledge proof for data ownership
   * @param {Object} ownershipData - Data for ownership proof
   * @param {string} ownershipData.dataVaultId - ID of the data vault
   * @param {string} ownershipData.owner - Address of the owner
   * @param {string} ownershipData.dataHash - Hash of the data
   * @returns {Promise<Object>} Generated ownership proof
   */
  async generateOwnershipProof(ownershipData) {
    try {
      logger.info(`Generating ownership proof for vault ${ownershipData.dataVaultId}`);

      const proofId = uuidv4();

      const circuitInputs = {
        dataVaultId: BigInt(ownershipData.dataVaultId).toString(),
        ownerAddress: this.hashFunction(ownershipData.owner),
        dataHash: ownershipData.dataHash,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex') // Cryptographically secure nonce
      };

      const { proof, publicSignals } = await this.prover.generateProof('ownership', circuitInputs);

      const ownershipProof = {
        id: proofId,
        type: 'ownership',
        proof,
        publicSignals,
        proofData: this.serializeProof(proof, publicSignals), // For on-chain use
        metadata: {
          dataVaultId: ownershipData.dataVaultId,
          owner: ownershipData.owner,
          dataHash: ownershipData.dataHash,
          timestamp: Date.now()
        },
        createdAt: Date.now()
      };

      this.proofs.set(proofId, ownershipProof);

      logger.info(`Ownership proof ${proofId} generated successfully`);
      return ownershipProof;
    } catch (error) {
      logger.error(`Failed to generate ownership proof:`, error);
      throw new Error(`Ownership proof generation failed: ${error.message}`);
    }
  }

  /**
   * Verify an ownership proof
   * @param {Object} proof - The ownership proof to verify
   * @returns {Promise<boolean>} Whether the proof is valid
   */
  async verifyOwnershipProof(proof) {
    try {
      logger.info(`Verifying ownership proof ${proof.id}`);

      const isValid = await this.verifier.verifyProof('ownership', proof.proof, proof.publicSignals);

      if (isValid) {
        logger.info(`Ownership proof ${proof.id} verified successfully`);
      } else {
        logger.warn(`Ownership proof ${proof.id} verification failed`);
      }

      return isValid;
    } catch (error) {
      logger.error(`Verification error for ownership proof ${proof.id}:`, error);
      return false;
    }
  }

  /**
   * Revoke a proof by ID
   * @param {string} proofId - ID of the proof to revoke
   * @returns {boolean} Whether the proof was successfully revoked
   */
  revokeProof(proofId) {
    if (this.proofs.has(proofId)) {
      this.proofs.delete(proofId);
      logger.info(`Proof ${proofId} revoked successfully`);
      return true;
    }
    logger.warn(`Proof ${proofId} not found for revocation`);
    return false;
  }

  /**
   * Generate verification key for a circuit
   * @param {string} circuitType - Type of circuit (e.g., 'access', 'computation', 'ownership')
   * @returns {Promise<Object>} Verification key
   */
  async generateVerificationKey(circuitType) {
    try {
      logger.info(`Generating verification key for circuit ${circuitType}`);

      const verificationKey = await this.verifier.generateVerificationKey(circuitType);

      this.verificationKeys.set(circuitType, verificationKey);

      logger.info(`Verification key for circuit ${circuitType} generated successfully`);
      return verificationKey;
    } catch (error) {
      logger.error(`Failed to generate verification key:`, error);
      throw new Error(`Verification key generation failed: ${error.message}`);
    }
  }

  /**
   * Get a verification key for a circuit
   * @param {string} circuitType - Type of circuit
   * @returns {Object|null} Verification key or null if not found
   */
  getVerificationKey(circuitType) {
    return this.verificationKeys.get(circuitType) || null;
  }

  /**
   * Get a proof by ID
   * @param {string} proofId - ID of the proof
   * @returns {Object|null} Proof object or null if not found
   */
  getProof(proofId) {
    return this.proofs.get(proofId) || null;
  }

  /**
   * Check if a proof is expired
   * @param {string} proofId - ID of the proof
   * @returns {boolean} Whether the proof is expired
   */
  isProofExpired(proofId) {
    const proof = this.proofs.get(proofId);
    if (!proof) return true;

    // Only access proofs expire
    if (proof.type !== 'access') return false;

    return proof.metadata.expiresAt < Date.now();
  }

  /**
   * Serialize a proof for on-chain verification
   * @param {Object} proof - Proof object
   * @param {Array} publicSignals - Public signals
   * @returns {string} Serialized proof
   * @private
   */
  serializeProof(proof, publicSignals) {
    const serializedProof = {
      a: proof.a,
      b: proof.b,
      c: proof.c,
      publicSignals
    };
    return JSON.stringify(serializedProof);
  }

  /**
   * Deserialize a proof from its on-chain representation
   * @param {string} serializedProof - Serialized proof
   * @returns {Object} Deserialized proof
   * @private
   */
  deserializeProof(serializedProof) {
    try {
      const parsed = JSON.parse(serializedProof);
      return {
        proof: {
          a: parsed.a,
          b: parsed.b,
          c: parsed.c
        },
        publicSignals: parsed.publicSignals
      };
    } catch (error) {
      logger.error(`Failed to deserialize proof:`, error);
      throw new Error(`Proof deserialization failed: ${error.message}`);
    }
  }
}

module.exports = ZKPAccessVerifier;
