/**
 * PrivaSight ZKP Hash Utilities
 * 
 * Implements specialized hash functions optimized for zero-knowledge proofs (ZKPs).
 * These hash functions are designed to be efficiently represented in arithmetic circuits
 * while maintaining strong cryptographic properties. Includes utility functions for
 * field elements, address hashing, and nonce generation.
 */

const { buildPoseidon } = require('circomlibjs');
const { keccak256, toChecksumAddress } = require('ethereumjs-util');
const { BigNumber } = require('ethers');
const crypto = require('crypto');
const logger = require('../../../utils/logger')('privacy-layer:zkp-hash');

// Cache for Poseidon instances
let poseidonInstance = null;
let poseidon2Instance = null;
let poseidon3Instance = null;
let poseidon4Instance = null;
let poseidon6Instance = null;

/**
 * Initialize Poseidon hash instances for different input lengths
 * @returns {Promise<void>}
 * @throws {Error} If initialization fails
 */
async function initializePoseidon() {
  try {
    if (!poseidonInstance) {
      logger.info('Initializing Poseidon hash instances');
      
      poseidonInstance = await buildPoseidon(); // Standard instance for variable inputs
      poseidon2Instance = await buildPoseidon({ t: 3, rf: 8, rp: 57 }); // 2 inputs
      poseidon3Instance = await buildPoseidon({ t: 4, rf: 8, rp: 57 }); // 3 inputs
      poseidon4Instance = await buildPoseidon({ t: 5, rf: 8, rp: 57 }); // 4 inputs
      poseidon6Instance = await buildPoseidon({ t: 7, rf: 8, rp: 57 }); // 6 inputs
      
      logger.info('Poseidon hash instances initialized successfully');
    }
  } catch (error) {
    logger.error('Failed to initialize Poseidon hash instances:', error);
    throw new Error(`Poseidon initialization failed: ${error.message}`);
  }
}

/**
 * Hash an array of inputs using Poseidon hash (ZK-friendly)
 * Automatically selects the most efficient instance based on input length
 * @param {Array<string|number|BigNumber>} inputs - Array of inputs to hash
 * @returns {Promise<string>} Resulting hash as a string
 * @throws {Error} If inputs are invalid or hashing fails
 */
async function poseidonHash(inputs) {
  if (!poseidonInstance) await initializePoseidon();

  try {
    if (!Array.isArray(inputs)) throw new Error('Inputs must be an array');
    if (inputs.length === 0) throw new Error('Inputs array cannot be empty');

    const preparedInputs = inputs.map((input, index) => {
      try {
        const bnInput = BigNumber.isBigNumber(input) ? input : BigNumber.from(input.toString());
        if (bnInput.lt(0)) throw new Error(`Input at index ${index} is negative`);
        return poseidonInstance.F.e(bnInput.toString());
      } catch (error) {
        throw new Error(`Invalid input at index ${index}: ${error.message}`);
      }
    });

    let result;
    switch (preparedInputs.length) {
      case 2: result = poseidon2Instance(preparedInputs); break;
      case 3: result = poseidon3Instance(preparedInputs); break;
      case 4: result = poseidon4Instance(preparedInputs); break;
      case 5:
      case 6: result = poseidon6Instance(preparedInputs); break;
      default: result = poseidonInstance(preparedInputs);
    }

    return poseidonInstance.F.toString(result);
  } catch (error) {
    logger.error('Poseidon hash error:', error);
    throw new Error(`Poseidon hash failed: ${error.message}`);
  }
}

/**
 * Synchronous version of Poseidon hash using cached instances
 * @param {Array<string|number|BigNumber>} inputs - Array of inputs to hash
 * @returns {string} Resulting hash as a string
 * @throws {Error} If Poseidon is not initialized or inputs are invalid
 */
function poseidonHashSync(inputs) {
  if (!poseidonInstance) throw new Error('Poseidon not initialized. Call initializePoseidon() first');

  try {
    if (!Array.isArray(inputs)) throw new Error('Inputs must be an array');
    if (inputs.length === 0) throw new Error('Inputs array cannot be empty');

    const preparedInputs = inputs.map((input, index) => {
      try {
        const bnInput = BigNumber.isBigNumber(input) ? input : BigNumber.from(input.toString());
        if (bnInput.lt(0)) throw new Error(`Input at index ${index} is negative`);
        return poseidonInstance.F.e(bnInput.toString());
      } catch (error) {
        throw new Error(`Invalid input at index ${index}: ${error.message}`);
      }
    });

    let result;
    switch (preparedInputs.length) {
      case 2: result = poseidon2Instance(preparedInputs); break;
      case 3: result = poseidon3Instance(preparedInputs); break;
      case 4: result = poseidon4Instance(preparedInputs); break;
      case 5:
      case 6: result = poseidon6Instance(preparedInputs); break;
      default: result = poseidonInstance(preparedInputs);
    }

    return poseidonInstance.F.toString(result);
  } catch (error) {
    logger.error('Poseidon hash error:', error);
    throw new Error(`Poseidon hash failed: ${error.message}`);
  }
}

/**
 * Generate a MiMC7 hash (ZK-friendly alternative)
 * @param {Array<string|number|BigNumber>} inputs - Array of inputs to hash
 * @param {string} [key='mimckey'] - MiMC key
 * @returns {Promise<string>} Resulting hash as a string
 * @throws {Error} If inputs are invalid or hashing fails
 */
async function mimc7Hash(inputs, key = 'mimckey') {
  try {
    const { mimc7 } = await import('circomlibjs');
    if (!Array.isArray(inputs)) throw new Error('Inputs must be an array');
    if (inputs.length === 0) throw new Error('Inputs array cannot be empty');

    const preparedInputs = inputs.map((input, index) => {
      try {
        return BigNumber.isBigNumber(input) ? input.toString() : input.toString();
      } catch (error) {
        throw new Error(`Invalid input at index ${index}: ${error.message}`);
      }
    });

    const result = mimc7.multiHash(preparedInputs, key);
    return mimc7.F.toString(result);
  } catch (error) {
    logger.error('MiMC7 hash error:', error);
    throw new Error(`MiMC7 hash failed: ${error.message}`);
  }
}

/**
 * Hash an Ethereum address to a field element
 * @param {string} address - Ethereum address to hash
 * @returns {string} Resulting hash as a string
 * @throws {Error} If address is invalid or hashing fails
 */
function hashAddress(address) {
  try {
    const { isAddress } = require('ethers').utils;
    if (!isAddress(address)) throw new Error('Invalid Ethereum address');
    const checksumAddress = toChecksumAddress(address);
    const addressBuffer = Buffer.from(checksumAddress.slice(2), 'hex');
    const hash = keccak256(addressBuffer);
    return BigNumber.from(hash).toString();
  } catch (error) {
    logger.error('Address hash error:', error);
    throw new Error(`Address hash failed: ${error.message}`);
  }
}

/**
 * Generate a Pedersen hash (ZK-friendly alternative)
 * @param {Array<string|number|BigNumber>} inputs - Array of inputs to hash
 * @returns {Promise<string>} Resulting hash as a string
 * @throws {Error} If inputs are invalid or hashing fails
 */
async function pedersenHash(inputs) {
  try {
    const { pedersen } = await import('circomlibjs');
    if (!Array.isArray(inputs)) throw new Error('Inputs must be an array');
    if (inputs.length === 0) throw new Error('Inputs array cannot be empty');

    const preparedInputs = inputs.map((input, index) => {
      try {
        return BigNumber.isBigNumber(input) ? input.toString() : input.toString();
      } catch (error) {
        throw new Error(`Invalid input at index ${index}: ${error.message}`);
      }
    });

    const result = pedersen.hash(preparedInputs);
    return pedersen.F.toString(result);
  } catch (error) {
    logger.error('Pedersen hash error:', error);
    throw new Error(`Pedersen hash failed: ${error.message}`);
  }
}

/**
 * Generate a SHA256 hash (non-ZK-friendly, for off-chain use)
 * @param {string|Buffer} input - Input to hash
 * @returns {string} Resulting hash as a hex string
 * @throws {Error} If input is invalid or hashing fails
 */
function sha256Hash(input) {
  try {
    if (typeof input !== 'string' && !Buffer.isBuffer(input)) throw new Error('Input must be a string or Buffer');
    const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
    const hash = crypto.createHash('sha256').update(buffer).digest('hex');
    return '0x' + hash;
  } catch (error) {
    logger.error('SHA256 hash error:', error);
    throw new Error(`SHA256 hash failed: ${error.message}`);
  }
}

/**
 * Generate a Keccak256 hash (non-ZK-friendly, for Ethereum compatibility)
 * @param {string|Buffer} input - Input to hash
 * @returns {string} Resulting hash as a hex string
 * @throws {Error} If input is invalid or hashing fails
 */
function keccak256Hash(input) {
  try {
    if (typeof input !== 'string' && !Buffer.isBuffer(input)) throw new Error('Input must be a string or Buffer');
    const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
    const hash = keccak256(buffer).toString('hex');
    return '0x' + hash;
  } catch (error) {
    logger.error('Keccak256 hash error:', error);
    throw new Error(`Keccak256 hash failed: ${error.message}`);
  }
}

/**
 * Convert input to a field element compatible with ZK circuits
 * @param {string|number|BigNumber} input - Input to convert
 * @param {number} [fieldSize=254] - Bit size of the field
 * @returns {string} Field element as a string
 * @throws {Error} If input is invalid or conversion fails
 */
function toFieldElement(input, fieldSize = 254) {
  try {
    if (typeof input !== 'string' && typeof input !== 'number' && !BigNumber.isBigNumber(input)) {
      throw new Error('Input must be a string, number, or BigNumber');
    }
    const bnInput = BigNumber.isBigNumber(input) ? input : BigNumber.from(input.toString());
    const fieldModulus = BigNumber.from(2).pow(fieldSize).sub(1);
    const fieldElement = bnInput.mod(fieldModulus);
    return fieldElement.toString();
  } catch (error) {
    logger.error('Field element conversion error:', error);
    throw new Error(`Field element conversion failed: ${error.message}`);
  }
}

/**
 * Combine multiple hashes into a single hash using Poseidon
 * @param {Array<string>} hashes - Array of hash strings to combine
 * @returns {Promise<string>} Combined hash as a string
 * @throws {Error} If hashes are invalid or combination fails
 */
async function combineHashes(hashes) {
  try {
    if (!Array.isArray(hashes)) throw new Error('Hashes must be an array');
    if (hashes.some(hash => typeof hash !== 'string')) throw new Error('All hashes must be strings');
    return await poseidonHash(hashes);
  } catch (error) {
    logger.error('Hash combination error:', error);
    throw new Error(`Hash combination failed: ${error.message}`);
  }
}

/**
 * Generate a random field element for ZK circuits
 * @param {number} [bitLength=254] - Bit length of the field element
 * @returns {string} Random field element as a string
 * @throws {Error} If bitLength is invalid or generation fails
 */
function randomFieldElement(bitLength = 254) {
  try {
    if (typeof bitLength !== 'number' || bitLength <= 0) throw new Error('bitLength must be a positive number');
    const byteLength = Math.ceil(bitLength / 8);
    const randomBytes = crypto.randomBytes(byteLength);
    let randomBigNumber = BigNumber.from(randomBytes);
    const fieldModulus = BigNumber.from(2).pow(bitLength).sub(1);
    randomBigNumber = randomBigNumber.mod(fieldModulus);
    return randomBigNumber.toString();
  } catch (error) {
    logger.error('Random field element generation error:', error);
    throw new Error(`Random field element generation failed: ${error.message}`);
  }
}

/**
 * Generate a secure nonce for ZK proofs
 * @returns {string} Secure nonce as a string
 */
function generateNonce() {
  return randomFieldElement();
}

module.exports = {
  poseidonHash,
  poseidonHashSync,
  mimc7Hash,
  pedersenHash,
  initializePoseidon,
  hashAddress,
  sha256Hash,
  keccak256Hash,
  toFieldElement,
  combineHashes,
  randomFieldElement,
  generateNonce
};
