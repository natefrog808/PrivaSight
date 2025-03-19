/**
 * PrivaSight ZKP Verifier
 * 
 * Implements proof verification for the PrivaSight privacy layer using zero-knowledge proofs.
 * This module handles the verification of proofs for access control, computation integrity,
 * and other privacy-preserving operations.
 */

const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const ethers = require('ethers');
const { performance } = require('perf_hooks');
const logger = require('../../../utils/logger')('privacy-layer:zkp-verifier');
const { poseidonHash } = require('../utils/hash');

// Cache for verification keys
const vkeyCache = new Map();

/**
 * ZKP Verifier class for verifying zero-knowledge proofs
 * @class ZKVerifier
 */
class ZKVerifier {
  /**
   * Create a new ZKP Verifier
   * @param {Object} options - Configuration options
   * @param {string} options.circuitsDir - Directory containing circuit artifacts
   * @param {Object} options.circuitConfig - Configuration for each circuit type
   * @param {boolean} [options.enableCaching=true] - Whether to cache verification keys
   * @param {Object} [options.contractAddresses={}] - Addresses of on-chain verifier contracts
   * @param {Object} [options.provider=null] - Ethers provider for on-chain verification
   * @throws {Error} If required options are missing or invalid
   */
  constructor({
    circuitsDir,
    circuitConfig,
    enableCaching = true,
    contractAddresses = {},
    provider = null
  }) {
    // Validate required options
    if (!circuitsDir || !fs.existsSync(circuitsDir)) {
      throw new Error('circuitsDir must be a valid directory path');
    }
    if (!circuitConfig || typeof circuitConfig !== 'object') {
      throw new Error('circuitConfig must be a valid object');
    }

    this.circuitsDir = circuitsDir;
    this.circuitConfig = circuitConfig;
    this.enableCaching = enableCaching;
    this.contractAddresses = contractAddresses;
    this.provider = provider;

    // Statistics tracking
    this.verificationRequests = 0;
    this.verificationSuccesses = 0;
    this.verificationFailures = 0;
    this.verificationTimes = [];

    logger.info('ZKP Verifier initialized with configuration:', {
      circuitsDir,
      enableCaching,
      hasProvider: !!provider
    });
  }

  /**
   * Verify a zero-knowledge proof
   * @param {string} circuitType - Type of circuit used
   * @param {Object} proof - The proof to verify
   * @param {Array<string>} publicSignals - Public signals from the proof
   * @param {Object} [options] - Additional options
   * @param {boolean} [options.useCache=true] - Whether to use cached verification keys
   * @param {boolean} [options.onChain=false] - Whether to verify on-chain
   * @param {boolean} [options.verbose=false] - Whether to log verbose output
   * @returns {Promise<boolean>} Whether the proof is valid
   * @throws {Error} If inputs are invalid or verification fails critically
   */
  async verifyProof(circuitType, proof, publicSignals, options = {}) {
    const startTime = performance.now();
    const { useCache = true, onChain = false, verbose = false } = options;

    try {
      // Input validation
      if (!this.circuitConfig[circuitType]) {
        throw new Error(`Unsupported circuit type: ${circuitType}`);
      }
      if (!this._isValidProofStructure(proof)) {
        throw new Error('Invalid proof structure');
      }
      if (!Array.isArray(publicSignals)) {
        throw new Error('publicSignals must be an array');
      }

      logger.info(`Verifying proof for circuit '${circuitType}'`);
      this.verificationRequests++;

      if (verbose) {
        logger.debug('Proof:', proof);
        logger.debug('Public signals:', publicSignals);
      }

      const isValid = onChain && this.provider
        ? await this._verifyProofOnChain(circuitType, proof, publicSignals)
        : await this._verifyProofOffChain(circuitType, proof, publicSignals, useCache);

      // Update statistics
      isValid ? this.verificationSuccesses++ : this.verificationFailures++;
      const verificationTime = Math.round(performance.now() - startTime);
      this.verificationTimes.push(verificationTime);

      logger.info(`Proof verification for '${circuitType}' result: ${isValid} (${verificationTime}ms)`);
      return isValid;
    } catch (error) {
      this.verificationFailures++;
      logger.error(`Failed to verify proof for '${circuitType}':`, error);
      return false;
    }
  }

  /**
   * Verify a batch of proofs for the same circuit type
   * @param {string} circuitType - Type of circuit used
   * @param {Array<{proof: Object, publicSignals: Array<string>}>} proofBatch - Array of proofs and signals
   * @param {Object} [options] - Additional options
   * @returns {Promise<Array<boolean>>} Array of verification results
   */
  async verifyProofBatch(circuitType, proofBatch, options = {}) {
    logger.info(`Verifying batch of ${proofBatch.length} proofs for '${circuitType}'`);
    return Promise.all(
      proofBatch.map(({ proof, publicSignals }) =>
        this.verifyProof(circuitType, proof, publicSignals, options)
      )
    );
  }

  /**
   * Verify a multi-circuit proof
   * @param {Array<{circuitType: string, proof: Object, publicSignals: Array<string>}>} proofs - Array of proofs
   * @param {Object} [options] - Additional options
   * @returns {Promise<boolean>} Whether all proofs are valid
   */
  async verifyMultiProof(proofs, options = {}) {
    logger.info(`Verifying multi-circuit proof with ${proofs.length} components`);
    try {
      const results = await Promise.all(
        proofs.map(({ circuitType, proof, publicSignals }) =>
          this.verifyProof(circuitType, proof, publicSignals, options)
        )
      );
      return results.every(result => result);
    } catch (error) {
      logger.error('Multi-circuit proof verification failed:', error);
      return false;
    }
  }

  /**
   * Verify an access proof with metadata checks
   * @param {Object} proof - Access proof
   * @param {Array<string>} publicSignals - Public signals
   * @param {Object} [metadata] - Verification metadata
   * @param {boolean} [metadata.checkExpiration=true] - Check expiration
   * @param {number} [metadata.currentTime] - Current timestamp
   * @param {string} [metadata.expectedMerkleRoot] - Expected Merkle root
   * @returns {Promise<boolean>} Whether the proof is valid
   */
  async verifyAccessProof(proof, publicSignals, metadata = {}) {
    logger.info(`Verifying access proof${metadata.accessId ? ` for ID ${metadata.accessId}` : ''}`);
    const signals = this._extractAccessPublicSignals(publicSignals);

    if (metadata.checkExpiration !== false && metadata.currentTime > parseInt(signals.timestamp)) {
      logger.warn(`Access expired: ${signals.timestamp} < ${metadata.currentTime}`);
      return false;
    }
    if (metadata.expectedMerkleRoot && metadata.expectedMerkleRoot !== signals.merkleRoot) {
      logger.warn(`Merkle root mismatch: expected ${metadata.expectedMerkleRoot}, got ${signals.merkleRoot}`);
      return false;
    }

    return this.verifyProof('access', proof, publicSignals, metadata);
  }

  /**
   * Verify a computation proof with metadata checks
   * @param {Object} proof - Computation proof
   * @param {Array<string>} publicSignals - Public signals
   * @param {Object} [metadata] - Verification metadata
   * @returns {Promise<boolean>} Whether the proof is valid
   */
  async verifyComputationProof(proof, publicSignals, metadata = {}) {
    logger.info(`Verifying computation proof${metadata.computationId ? ` for ID ${metadata.computationId}` : ''}`);
    const signals = this._extractComputationPublicSignals(publicSignals);

    if (metadata.allowedComputationTypes && !metadata.allowedComputationTypes.includes(Number(signals.computationType))) {
      logger.warn(`Invalid computation type: ${signals.computationType}`);
      return false;
    }
    if (metadata.expectedPrivacyBudgetHash && metadata.expectedPrivacyBudgetHash !== signals.privacyBudgetHash) {
      logger.warn(`Privacy budget mismatch: expected ${metadata.expectedPrivacyBudgetHash}, got ${signals.privacyBudgetHash}`);
      return false;
    }
    if (metadata.expectedValidatorsMerkleRoot && metadata.expectedValidatorsMerkleRoot !== signals.validatorsMerkleRoot) {
      logger.warn(`Validators root mismatch: expected ${metadata.expectedValidatorsMerkleRoot}, got ${signals.validatorsMerkleRoot}`);
      return false;
    }
    if (metadata.expectedResultHash && metadata.expectedResultHash !== signals.resultHash) {
      logger.warn(`Result hash mismatch: expected ${metadata.expectedResultHash}, got ${signals.resultHash}`);
      return false;
    }

    return this.verifyProof('computation', proof, publicSignals, metadata);
  }

  /**
   * Verify an ownership proof
   * @param {Object} proof - Ownership proof
   * @param {Array<string>} publicSignals - Public signals
   * @param {Object} [metadata] - Verification metadata
   * @returns {Promise<boolean>} Whether the proof is valid
   */
  async verifyOwnershipProof(proof, publicSignals, metadata = {}) {
    logger.info(`Verifying ownership proof${metadata.dataVaultId ? ` for ID ${metadata.dataVaultId}` : ''}`);
    return this.verifyProof('ownership', proof, publicSignals, metadata);
  }

  /**
   * Generate a verification key for a circuit
   * @param {string} circuitType - Circuit type
   * @returns {Promise<Object>} Verification key
   */
  async generateVerificationKey(circuitType) {
    if (this.enableCaching && vkeyCache.has(circuitType)) {
      return vkeyCache.get(circuitType);
    }

    const vkeyPath = this._getVerificationKeyPath(circuitType);
    try {
      const verificationKey = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
      if (this.enableCaching) vkeyCache.set(circuitType, verificationKey);
      return verificationKey;
    } catch (error) {
      logger.error(`Failed to load verification key for '${circuitType}':`, error);
      throw error;
    }
  }

  /**
   * Export a verification key to Solidity verifier format
   * @param {string} circuitType - Circuit type
   * @param {string} [outputPath] - Output file path
   * @returns {Promise<string>} Solidity code
   */
  async exportSolidityVerifier(circuitType, outputPath) {
    const verificationKey = await this.generateVerificationKey(circuitType);
    const solidityCode = await snarkjs.zKey.exportSolidityVerifier(verificationKey, { groth16: true });
    if (outputPath) fs.writeFileSync(outputPath, solidityCode);
    return solidityCode;
  }

  /**
   * Get verification statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    const total = this.verificationRequests;
    const avgTime = this.verificationTimes.length
      ? this.verificationTimes.reduce((sum, t) => sum + t, 0) / this.verificationTimes.length
      : 0;
    return {
      totalVerifications: total,
      successfulVerifications: this.verificationSuccesses,
      failedVerifications: this.verificationFailures,
      successRate: total ? (this.verificationSuccesses / total * 100).toFixed(2) : 0,
      averageVerificationTime: Math.round(avgTime)
    };
  }

  /**
   * Reset verification statistics
   */
  resetStatistics() {
    this.verificationRequests = 0;
    this.verificationSuccesses = 0;
    this.verificationFailures = 0;
    this.verificationTimes = [];
    logger.info('Statistics reset');
  }

  /**
   * Verify proof off-chain
   * @private
   */
  async _verifyProofOffChain(circuitType, proof, publicSignals, useCache) {
    try {
      const verificationKey = await this._getVerificationKey(circuitType, useCache);
      return await snarkjs.groth16.verify(verificationKey, publicSignals, proof);
    } catch (error) {
      logger.warn('Off-chain verification failed:', error.message);
      return false;
    }
  }

  /**
   * Verify proof on-chain
   * @private
   */
  async _verifyProofOnChain(circuitType, proof, publicSignals) {
    if (!this.provider) throw new Error('No provider for on-chain verification');
    const address = this.contractAddresses[circuitType];
    if (!address) throw new Error(`No contract address for '${circuitType}'`);

    const formattedProof = this._formatProofForSolidity(proof);
    const abi = ['function verifyProof(uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[] memory input) view returns (bool)'];
    const contract = new ethers.Contract(address, abi, this.provider);

    try {
      return await contract.verifyProof(
        [formattedProof[0], formattedProof[1]],
        [[formattedProof[2], formattedProof[3]], [formattedProof[4], formattedProof[5]]],
        [formattedProof[6], formattedProof[7]],
        publicSignals
      );
    } catch (error) {
      logger.warn('On-chain verification failed:', error.reason || error.message);
      return false;
    }
  }

  /**
   * Get verification key
   * @private
   */
  async _getVerificationKey(circuitType, useCache) {
    if (useCache && this.enableCaching && vkeyCache.has(circuitType)) {
      return vkeyCache.get(circuitType);
    }
    return this.generateVerificationKey(circuitType);
  }

  /**
   * Format proof for Solidity
   * @private
   */
  _formatProofForSolidity(proof) {
    return [
      proof.pi_a[0], proof.pi_a[1],
      proof.pi_b[0][1], proof.pi_b[0][0],
      proof.pi_b[1][1], proof.pi_b[1][0],
      proof.pi_c[0], proof.pi_c[1]
    ];
  }

  /**
   * Extract access public signals
   * @private
   */
  _extractAccessPublicSignals(publicSignals) {
    if (publicSignals.length < 4) throw new Error('Insufficient access public signals');
    return {
      dataVaultId: publicSignals[0],
      accessHash: publicSignals[1],
      timestamp: publicSignals[2],
      merkleRoot: publicSignals[3]
    };
  }

  /**
   * Extract computation public signals
   * @private
   */
  _extractComputationPublicSignals(publicSignals) {
    if (publicSignals.length < 5) throw new Error('Insufficient computation public signals');
    return {
      computationHash: publicSignals[0],
      resultHash: publicSignals[1],
      computationType: publicSignals[2],
      privacyBudgetHash: publicSignals[3],
      validatorsMerkleRoot: publicSignals[4]
    };
  }

  /**
   * Validate proof structure
   * @private
   */
  _isValidProofStructure(proof) {
    return (
      proof &&
      Array.isArray(proof.pi_a) && proof.pi_a.length === 2 &&
      Array.isArray(proof.pi_b) && proof.pi_b.length === 2 && proof.pi_b.every(arr => arr.length === 2) &&
      Array.isArray(proof.pi_c) && proof.pi_c.length === 2
    );
  }

  /**
   * Get verification key path
   * @private
   */
  _getVerificationKeyPath(circuitType) {
    return path.join(this.circuitsDir, `${circuitType}.vkey.json`);
  }
}

// Singleton instance
module.exports = {
  ZKVerifier,
  verifier: new ZKVerifier({
    circuitsDir: path.resolve(__dirname, '../circuits'),
    circuitConfig: {
      access: { description: 'Access control circuit', maxConstraints: 50000 },
      computation: { description: 'Computation verification circuit', maxConstraints: 200000 },
      ownership: { description: 'Data ownership circuit', maxConstraints: 30000 }
    },
    enableCaching: true,
    contractAddresses: {
      access: process.env.ACCESS_VERIFIER_ADDRESS,
      computation: process.env.COMPUTATION_VERIFIER_ADDRESS,
      ownership: process.env.OWNERSHIP_VERIFIER_ADDRESS
    },
    provider: null
  })
};
