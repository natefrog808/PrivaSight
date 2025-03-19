/**
 * PrivaSight ZKP Prover
 * 
 * Implements proof generation for the PrivaSight privacy layer using zero-knowledge proofs.
 * This module handles the creation and verification of proofs for access control, 
 * computation verification, and other privacy-preserving operations using the snarkjs library.
 */

const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const crypto = require('crypto');
const { performance } = require('perf_hooks');
const { BigNumber } = require('ethers');
const { bufferToHex, keccak256 } = require('ethereumjs-util');
const logger = require('../../../utils/logger')('privacy-layer:zkp-prover');
const { poseidonHash } = require('../utils/hash');

// Cache for compiled circuits and verification keys
const circuitCache = new Map();

/**
 * ZKP Prover class for generating and verifying zero-knowledge proofs
 * @class ZKProver
 */
class ZKProver {
  /**
   * Create a new ZKP Prover
   * @param {Object} options - Configuration options
   * @param {string} options.circuitsDir - Directory containing circuit artifacts
   * @param {Object} options.circuitConfig - Configuration for each circuit type
   * @param {boolean} [options.enableOptimization=true] - Enable proof generation optimizations
   * @param {boolean} [options.enableParallelization=true] - Enable parallel proof generation
   * @param {Object} [options.cache] - Cache configuration options
   * @throws {Error} If required options are missing or invalid
   */
  constructor({
    circuitsDir,
    circuitConfig,
    enableOptimization = true,
    enableParallelization = true,
    cache = { enabled: true, maxSize: 100 }
  }) {
    if (!circuitsDir || !fs.existsSync(circuitsDir)) {
      throw new Error('circuitsDir must be a valid directory path');
    }
    if (!circuitConfig || typeof circuitConfig !== 'object') {
      throw new Error('circuitConfig must be a valid object');
    }

    this.circuitsDir = circuitsDir;
    this.circuitConfig = circuitConfig;
    this.enableOptimization = enableOptimization;
    this.enableParallelization = enableParallelization;
    this.cache = cache;

    // Proof cache (input hash -> proof)
    this.proofCache = new Map();

    // Track initialized circuits
    this.initializedCircuits = new Set();

    logger.info('ZKP Prover initialized with configuration:', {
      circuitsDir,
      enableOptimization,
      enableParallelization,
      cacheEnabled: cache.enabled,
      cacheMaxSize: cache.maxSize
    });
  }

  /**
   * Generate a zero-knowledge proof for a circuit
   * @param {string} circuitType - Type of circuit (e.g., 'access', 'computation')
   * @param {Object} inputs - Circuit inputs
   * @param {Object} [options] - Additional options
   * @param {boolean} [options.useCache=true] - Use cached proofs if available
   * @param {boolean} [options.verbose=false] - Log detailed output
   * @returns {Promise<Object>} Generated proof, public signals, and metadata
   * @throws {Error} If proof generation fails
   */
  async generateProof(circuitType, inputs, options = {}) {
    const startTime = performance.now();
    const { useCache = true, verbose = false } = options;

    try {
      logger.info(`Generating proof for circuit '${circuitType}'`);
      if (verbose) logger.debug(`Inputs for ${circuitType} proof:`, inputs);

      // Validate circuit type
      if (!this.circuitConfig[circuitType]) {
        throw new Error(`Unsupported circuit type: ${circuitType}`);
      }

      // Initialize circuit lazily
      if (!this.initializedCircuits.has(circuitType)) {
        await this._initializeCircuit(circuitType);
        this.initializedCircuits.add(circuitType);
      }

      // Check cache
      let inputHash;
      if (useCache && this.cache.enabled) {
        inputHash = this._hashInputs(circuitType, inputs);
        const cachedProof = this.proofCache.get(inputHash);
        if (cachedProof) {
          logger.info(`Using cached proof for circuit '${circuitType}'`);
          return cachedProof;
        }
      }

      // Prepare and validate inputs
      const preparedInputs = await this._prepareInputs(circuitType, inputs);

      // Get circuit paths
      const circuitPaths = this._getCircuitPaths(circuitType);

      // Generate witness
      const witnessStart = performance.now();
      const witness = await this._generateWitness(circuitType, preparedInputs);
      logger.debug(`Witness generated in ${Math.round(performance.now() - witnessStart)}ms`);

      // Generate proof
      const proofStart = performance.now();
      const { proof, publicSignals } = await this._generateSnarkProof(
        circuitPaths.zkeyPath,
        witness,
        this.enableOptimization
      );
      logger.debug(`Proof generated in ${Math.round(performance.now() - proofStart)}ms`);

      // Format for Solidity
      const solidityProof = this._formatProofForSolidity(proof);

      // Construct result
      const result = {
        proof,
        publicSignals,
        solidityProof,
        metadata: {
          circuitType,
          generatedAt: Date.now(),
          witness: verbose ? witness : undefined,
          generationTime: Math.round(performance.now() - startTime)
        }
      };

      // Cache result
      if (useCache && this.cache.enabled) {
        this._cacheProof(inputHash, result);
      }

      logger.info(`Proof generated for circuit '${circuitType}' in ${result.metadata.generationTime}ms`);
      return result;
    } catch (error) {
      logger.error(`Failed to generate proof for circuit '${circuitType}':`, error);
      throw new Error(`Proof generation failed: ${error.message}`);
    }
  }

  /**
   * Generate a batch of proofs for the same circuit type
   * @param {string} circuitType - Type of circuit
   * @param {Array<Object>} inputsArray - Array of input objects
   * @param {Object} [options] - Additional options
   * @param {number} [options.maxConcurrent=4] - Max concurrent proofs in parallel mode
   * @returns {Promise<Array<Object>>} Array of generated proofs
   */
  async generateProofBatch(circuitType, inputsArray, options = {}) {
    const { maxConcurrent = 4, ...restOptions } = options;
    logger.info(`Generating batch of ${inputsArray.length} proofs for circuit '${circuitType}'`);

    if (!Array.isArray(inputsArray)) {
      throw new Error('inputsArray must be an array');
    }

    if (!this.enableParallelization) {
      // Sequential generation
      const results = [];
      for (const inputs of inputsArray) {
        results.push(await this.generateProof(circuitType, inputs, restOptions));
      }
      return results;
    } else {
      // Parallel generation with concurrency limit
      const proofPromises = [];
      for (let i = 0; i < inputsArray.length; i += maxConcurrent) {
        const batch = inputsArray.slice(i, i + maxConcurrent).map(inputs =>
          this.generateProof(circuitType, inputs, restOptions)
        );
        proofPromises.push(...(await Promise.all(batch)));
      }
      return proofPromises;
    }
  }

  /**
   * Generate a multi-circuit proof (collection of individual proofs)
   * @param {Array<{circuitType: string, inputs: Object}>} circuits - Circuit types and inputs
   * @param {Object} [options] - Additional options
   * @returns {Promise<Object>} Composite proof object
   * @note Each proof must be verified individually
   */
  async generateMultiProof(circuits, options = {}) {
    logger.info(`Generating multi-circuit proof with ${circuits.length} circuits`);

    if (!Array.isArray(circuits)) {
      throw new Error('circuits must be an array');
    }

    try {
      const proofs = await Promise.all(
        circuits.map(({ circuitType, inputs }) =>
          this.generateProof(circuitType, inputs, options)
        )
      );

      return {
        proofs,
        metadata: {
          circuitTypes: circuits.map(c => c.circuitType),
          generatedAt: Date.now()
        }
      };
    } catch (error) {
      logger.error('Failed to generate multi-circuit proof:', error);
      throw new Error(`Multi-circuit proof generation failed: ${error.message}`);
    }
  }

  /**
   * Verify a proof locally
   * @param {string} circuitType - Type of circuit
   * @param {Object} proof - Proof to verify
   * @param {Array<string>} publicSignals - Public signals
   * @returns {Promise<boolean>} Verification result
   */
  async verifyProof(circuitType, proof, publicSignals) {
    try {
      logger.info(`Verifying proof for circuit '${circuitType}'`);

      if (!this.initializedCircuits.has(circuitType)) {
        await this._initializeCircuit(circuitType);
        this.initializedCircuits.add(circuitType);
      }

      const { verificationKey } = circuitCache.get(circuitType);
      if (!verificationKey) {
        throw new Error(`Verification key not loaded for circuit '${circuitType}'`);
      }

      const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, proof);
      logger.info(`Proof verification result for circuit '${circuitType}': ${isValid}`);
      return isValid;
    } catch (error) {
      logger.error(`Failed to verify proof for circuit '${circuitType}':`, error);
      return false;
    }
  }

  /**
   * Generate an access control proof
   * @param {Object} accessData - Access control data
   * @returns {Promise<Object>} Access proof
   * @throws {Error} If required fields are missing or invalid
   */
  async generateAccessProof(accessData) {
    const requiredFields = [
      'dataVaultId', 'researcherAddress', 'accessType', 'timestamp',
      'expirationTime', 'accessTermsHash', 'ownerSignatureR', 'ownerSignatureS',
      'ownerPublicKey', 'merkleRoot', 'merklePath', 'merklePathIndices'
    ];
    this._validateInputs(accessData, requiredFields);

    return this.generateProof('access', {
      dataVaultId: BigNumber.from(accessData.dataVaultId).toString(),
      researcherAddress: BigNumber.from(accessData.researcherAddress).toString(),
      accessType: accessData.accessType,
      timestamp: BigNumber.from(accessData.timestamp).toString(),
      expirationTime: BigNumber.from(accessData.expirationTime).toString(),
      accessTermsHash: accessData.accessTermsHash,
      ownerSignatureR: accessData.ownerSignatureR,
      ownerSignatureS: accessData.ownerSignatureS,
      ownerPublicKey: accessData.ownerPublicKey,
      merkleRoot: accessData.merkleRoot,
      merklePathIndices: accessData.merklePathIndices,
      merklePath: accessData.merklePath,
      nonce: this._generateNonce()
    });
  }

  /**
   * Generate a computation verification proof
   * @param {Object} computationData - Computation data
   * @returns {Promise<Object>} Computation proof
   * @throws {Error} If required fields are missing or invalid
   */
  async generateComputationProof(computationData) {
    const requiredFields = [
      'researcherAddress', 'dataVaultIds', 'dataVaultAccessHashes',
      'computationType', 'privacyParameters', 'featureSelectionMask',
      'featureCount', 'noiseSeeds', 'resultContributions'
    ];
    this._validateInputs(computationData, requiredFields);

    if (computationData.dataVaultIds.length !== computationData.dataVaultAccessHashes.length) {
      throw new Error('dataVaultIds and dataVaultAccessHashes must have the same length');
    }

    return this.generateProof('computation', {
      researcherAddress: BigNumber.from(computationData.researcherAddress).toString(),
      dataVaultIds: computationData.dataVaultIds.map(id => BigNumber.from(id).toString()),
      dataVaultCount: computationData.dataVaultIds.length,
      dataVaultAccessHashes: computationData.dataVaultAccessHashes,
      computationType: computationData.computationType,
      computationNonce: this._generateNonce(),
      privacyEpsilon: computationData.privacyParameters.epsilon,
      privacyDelta: computationData.privacyParameters.delta,
      featureSelectionMask: computationData.featureSelectionMask,
      featureCount: computationData.featureCount,
      computationTimestamp: BigNumber.from(Date.now()).toString(),
      noiseSeeds: computationData.noiseSeeds,
      resultContributions: computationData.resultContributions,
      validatorSignaturesR: computationData.validatorSignaturesR || [],
      validatorSignaturesS: computationData.validatorSignaturesS || [],
      validatorPublicKeys: computationData.validatorPublicKeys || [],
      validatorMerklePaths: computationData.validatorMerklePaths || [],
      validatorMerkleIndices: computationData.validatorMerkleIndices || []
    });
  }

  /**
   * Validate input object against required fields
   * @param {Object} inputs - Input object
   * @param {Array<string>} requiredFields - List of required field names
   * @private
   */
  _validateInputs(inputs, requiredFields) {
    for (const field of requiredFields) {
      if (!(field in inputs)) {
        throw new Error(`Missing required field: ${field}`);
      }
    }
  }

  /**
   * Generate a witness for a circuit
   * @param {string} circuitType - Type of circuit
   * @param {Object} inputs - Circuit inputs
   * @returns {Promise<Uint8Array>} Generated witness
   * @private
   */
  async _generateWitness(circuitType, inputs) {
    const { witnessCalculator } = circuitCache.get(circuitType);
    if (!witnessCalculator) {
      throw new Error(`Circuit '${circuitType}' not initialized`);
    }
    return witnessCalculator.calculateWTNSBin(inputs, 0);
  }

  /**
   * Generate a snark proof using the witness
   * @param {string} zkeyPath - Path to zkey file
   * @param {Uint8Array} witness - Witness data
   * @param {boolean} optimize - Use optimized settings
   * @returns {Promise<Object>} Proof and public signals
   * @private
   */
  async _generateSnarkProof(zkeyPath, witness, optimize = true) {
    const opts = optimize ? { numThreads: 8, parallelExecution: true } : {};
    return snarkjs.groth16.prove(zkeyPath, witness, opts);
  }

  /**
   * Load witness calculator for a circuit
   * @param {string} wasmPath - Path to WebAssembly file
   * @returns {Promise<Object>} Witness calculator
   * @private
   */
  async _loadWitnessCalculator(wasmPath) {
    const wasmBuffer = fs.readFileSync(wasmPath);
    const { default: wasm } = await import(`file://${path.resolve(wasmPath)}`);
    return wasm;
  }

  /**
   * Initialize a circuit and cache its components
   * @param {string} circuitType - Type of circuit
   * @private
   */
  async _initializeCircuit(circuitType) {
    logger.info(`Initializing circuit '${circuitType}'`);
    const circuitPaths = this._getCircuitPaths(circuitType);

    for (const [key, filePath] of Object.entries(circuitPaths)) {
      if (!fs.existsSync(filePath)) {
        throw new Error(`${key} not found for circuit '${circuitType}': ${filePath}`);
      }
    }

    const witnessCalculator = await this._loadWitnessCalculator(circuitPaths.wasmPath);
    const verificationKey = JSON.parse(fs.readFileSync(circuitPaths.vkeyPath, 'utf8'));

    circuitCache.set(circuitType, { witnessCalculator, verificationKey });
    logger.info(`Circuit '${circuitType}' initialized successfully`);
  }

  /**
   * Prepare inputs for a circuit
   * @param {string} circuitType - Type of circuit
   * @param {Object} inputs - Raw inputs
   * @returns {Promise<Object>} Prepared inputs
   * @private
   */
  async _prepareInputs(circuitType, inputs) {
    switch (circuitType) {
      case 'access':
        return this._prepareAccessInputs(inputs);
      case 'computation':
        return this._prepareComputationInputs(inputs);
      case 'ownership':
        return this._prepareOwnershipInputs(inputs);
      default:
        return inputs;
    }
  }

  /**
   * Prepare inputs for access circuit
   * @param {Object} inputs - Raw inputs
   * @returns {Object} Prepared inputs
   * @private
   */
  _prepareAccessInputs(inputs) {
    const preparedInputs = { ...inputs };
    const pathLength = 32;

    if (preparedInputs.merklePath.length > pathLength) {
      throw new Error(`merklePath exceeds maximum length of ${pathLength}`);
    }

    preparedInputs.merklePath = [
      ...preparedInputs.merklePath,
      ...Array(pathLength - preparedInputs.merklePath.length).fill('0')
    ];
    preparedInputs.merklePathIndices = [
      ...preparedInputs.merklePathIndices,
      ...Array(pathLength - preparedInputs.merklePathIndices.length).fill(0)
    ];

    preparedInputs.accessHash = preparedInputs.accessHash || poseidonHash([
      preparedInputs.dataVaultId,
      preparedInputs.researcherAddress,
      preparedInputs.nonce
    ]);

    return preparedInputs;
  }

  /**
   * Prepare inputs for computation circuit
   * @param {Object} inputs - Raw inputs
   * @returns {Object} Prepared inputs
   * @private
   */
  _prepareComputationInputs(inputs) {
    const preparedInputs = { ...inputs };
    const maxVaults = 10;
    const maxFeatures = 50;

    if (preparedInputs.dataVaultIds.length > maxVaults) {
      throw new Error(`dataVaultIds exceeds maximum length of ${maxVaults}`);
    }

    preparedInputs.computationHash = preparedInputs.computationHash || poseidonHash([
      poseidonHash([
        preparedInputs.computationType,
        preparedInputs.researcherAddress,
        preparedInputs.computationNonce,
        preparedInputs.dataVaultCount,
        preparedInputs.featureCount
      ]),
      poseidonHash([
        Math.round(preparedInputs.privacyEpsilon * 1e6),
        Math.round(preparedInputs.privacyDelta * 1e15),
        preparedInputs.computationTimestamp
      ]),
      preparedInputs.resultHash || poseidonHash([
        preparedInputs.resultContributions.reduce((a, b) => BigNumber.from(a).add(b).toString(), '0'),
        preparedInputs.computationNonce
      ]),
      preparedInputs.computationNonce
    ]);

    preparedInputs.resultHash = preparedInputs.resultHash || poseidonHash([
      preparedInputs.resultContributions.reduce((a, b) => BigNumber.from(a).add(b).toString(), '0'),
      preparedInputs.computationNonce
    ]);

    preparedInputs.privacyBudgetHash = poseidonHash([
      poseidonHash([
        Math.round(preparedInputs.privacyEpsilon * 1e6),
        Math.round(preparedInputs.privacyDelta * 1e15),
        preparedInputs.computationTimestamp
      ]),
      preparedInputs.computationNonce
    ]);

    const padArray = (arr, max, fill) => [
      ...arr,
      ...Array(max - arr.length).fill(fill)
    ];

    preparedInputs.dataVaultIds = padArray(preparedInputs.dataVaultIds, maxVaults, '0');
    preparedInputs.dataVaultAccessHashes = padArray(preparedInputs.dataVaultAccessHashes, maxVaults, '0');
    preparedInputs.noiseSeeds = padArray(preparedInputs.noiseSeeds, maxVaults, '0');
    preparedInputs.resultContributions = padArray(preparedInputs.resultContributions, maxVaults, 0);
    preparedInputs.featureSelectionMask = padArray(preparedInputs.featureSelectionMask, maxFeatures, 0);

    return preparedInputs;
  }

  /**
   * Prepare inputs for ownership circuit
   * @param {Object} inputs - Raw inputs
   * @returns {Object} Prepared inputs
   * @private
   */
  _prepareOwnershipInputs(inputs) {
    return { ...inputs };
  }

  /**
   * Get paths to circuit artifacts
   * @param {string} circuitType - Type of circuit
   * @returns {Object} Paths to circuit artifacts
   * @private
   */
  _getCircuitPaths(circuitType) {
    const config = this.circuitConfig[circuitType];
    if (!config) throw new Error(`Configuration not found for circuit type: ${circuitType}`);

    return {
      circuitPath: path.join(this.circuitsDir, `${circuitType}.circom`),
      wasmPath: path.join(this.circuitsDir, `${circuitType}_js/${circuitType}.wasm`),
      zkeyPath: path.join(this.circuitsDir, `${circuitType}.zkey`),
      vkeyPath: path.join(this.circuitsDir, `${circuitType}.vkey.json`)
    };
  }

  /**
   * Format proof for Solidity contracts
   * @param {Object} proof - Original proof
   * @returns {Array<string>} Formatted proof
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
   * Generate a cryptographically secure nonce
   * @returns {string} Random nonce
   * @private
   */
  _generateNonce() {
    return BigNumber.from(crypto.randomBytes(16)).toString();
  }

  /**
   * Hash inputs for caching
   * @param {string} circuitType - Type of circuit
   * @param {Object} inputs - Circuit inputs
   * @returns {string} Hash of inputs
   * @private
   */
  _hashInputs(circuitType, inputs) {
    const inputString = JSON.stringify({ circuitType, inputs });
    return bufferToHex(keccak256(Buffer.from(inputString)));
  }

  /**
   * Cache a proof with size limit
   * @param {string} key - Cache key
   * @param {Object} proof - Proof to cache
   * @private
   */
  _cacheProof(key, proof) {
    this.proofCache.set(key, proof);
    if (this.proofCache.size > this.cache.maxSize) {
      const firstKey = this.proofCache.keys().next().value;
      this.proofCache.delete(firstKey);
    }
  }

  /**
   * Clear proof and circuit caches
   */
  clearCache() {
    this.proofCache.clear();
    circuitCache.clear();
    this.initializedCircuits.clear();
    logger.info('All caches cleared');
  }

  /**
   * Load and return a verification key
   * @param {string} circuitType - Type of circuit
   * @returns {Promise<Object>} Verification key
   */
  async generateVerificationKey(circuitType) {
    if (!this.initializedCircuits.has(circuitType)) {
      await this._initializeCircuit(circuitType);
      this.initializedCircuits.add(circuitType);
    }
    const { verificationKey } = circuitCache.get(circuitType);
    return verificationKey;
  }
}

// Export class and singleton instance
module.exports = {
  ZKProver,
  prover: new ZKProver({
    circuitsDir: path.resolve(__dirname, '../circuits'),
    circuitConfig: {
      access: { description: 'Access control circuit', maxConstraints: 50000 },
      computation: { description: 'Computation verification circuit', maxConstraints: 200000 },
      ownership: { description: 'Data ownership circuit', maxConstraints: 30000 }
    },
    enableOptimization: true,
    enableParallelization: true,
    cache: { enabled: true, maxSize: 100 }
  })
};
