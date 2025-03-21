/**
 * PrivaSight SMPC Secret Sharing Implementation
 *
 * This module implements various secret sharing schemes for secure multi-party
 * computation. It supports Shamir's Secret Sharing, Additive Secret Sharing,
 * Replicated Secret Sharing, and hybrid approaches for optimal performance
 * and security in different scenarios.
 */

const crypto = require('crypto');
const { BigNumber } = require('ethers');
const { randomFieldElement } = require('../zkp/utils/hash');
const logger = require('../../utils/logger')('privacy-layer:secret-sharing');

// Prime field size (2^256 - 351)
const FIELD_PRIME = BigNumber.from('115792089237316195423570985008687907853269984665640564039457584007908834671663');

/**
 * Enumeration of supported secret sharing schemes
 * @enum {string}
 */
const SecretSharingScheme = {
  SHAMIR: 'shamir',
  ADDITIVE: 'additive',
  REPLICATED: 'replicated',
  HYBRID: 'hybrid'
};

/**
 * Secret sharing implementation for secure multi-party computation
 * @class SecretSharing
 */
class SecretSharing {
  /**
   * Create a new Secret Sharing instance
   * @param {Object} options - Configuration options
   * @param {string} [options.defaultScheme=SecretSharingScheme.SHAMIR] - Default sharing scheme
   * @param {BigNumber} [options.fieldPrime=FIELD_PRIME] - Prime field for modular arithmetic
   * @param {Object} [options.schemeConfig] - Configuration for specific schemes
   * @param {boolean} [options.enableVerifiableSharing=false] - Whether to enable verifiable secret sharing
   */
  constructor({
    defaultScheme = SecretSharingScheme.SHAMIR,
    fieldPrime = FIELD_PRIME,
    schemeConfig = {},
    enableVerifiableSharing = false
  } = {}) {
    this.defaultScheme = defaultScheme;
    this.fieldPrime = fieldPrime;
    this.schemeConfig = schemeConfig;
    this.enableVerifiableSharing = enableVerifiableSharing;

    logger.info(`Secret Sharing initialized with ${defaultScheme} scheme`);
  }

  /**
   * Share a secret using the specified scheme
   * @param {Object} params - Sharing parameters
   * @param {string|number|BigNumber} params.secret - Secret to share
   * @param {number} params.numShares - Number of shares to create
   * @param {number} params.threshold - Minimum shares needed for reconstruction
   * @param {string} [params.scheme] - Sharing scheme to use (defaults to instance default)
   * @param {Object} [params.metadata] - Additional metadata
   * @returns {Promise<Array<Object>>} Generated shares
   */
  async shareSecret({ secret, numShares, threshold, scheme, metadata = {} }) {
    try {
      // Input validation
      if (secret === undefined || secret === null) {
        throw new Error('Secret is required');
      }
      if (!numShares || numShares < 2) {
        throw new Error('At least 2 shares are required');
      }
      if (!threshold || threshold < 1 || threshold > numShares) {
        throw new Error(`Threshold must be between 1 and ${numShares}`);
      }

      // Determine the scheme to use
      const selectedScheme = scheme || this.defaultScheme;

      // Convert secret to BigNumber for arithmetic operations
      const secretValue = BigNumber.isBigNumber(secret)
        ? secret
        : BigNumber.from(secret.toString());

      // Generate shares based on the selected scheme
      let shares;
      switch (selectedScheme) {
        case SecretSharingScheme.SHAMIR:
          shares = this._shamir(secretValue, numShares, threshold);
          break;
        case SecretSharingScheme.ADDITIVE:
          shares = this._additive(secretValue, numShares, threshold);
          break;
        case SecretSharingScheme.REPLICATED:
          shares = this._replicated(secretValue, numShares, threshold);
          break;
        case SecretSharingScheme.HYBRID:
          shares = this._hybrid(secretValue, numShares, threshold);
          break;
        default:
          throw new Error(`Unsupported secret sharing scheme: ${selectedScheme}`);
      }

      // Enhance shares with metadata and optional verification
      const enhancedShares = this._enhanceShares(shares, {
        scheme: selectedScheme,
        threshold,
        metadata,
        verifiable: this.enableVerifiableSharing
      });

      logger.info(`Successfully created ${numShares} shares using ${selectedScheme} scheme`);
      return enhancedShares;
    } catch (error) {
      logger.error('Secret sharing failed:', error);
      throw new Error(`Secret sharing failed: ${error.message}`);
    }
  }

  /**
   * Reconstruct a secret from shares
   * @param {Object} params - Reconstruction parameters
   * @param {Array<Object>} params.shares - Shares to reconstruct from
   * @param {string} [params.scheme] - Sharing scheme used
   * @param {boolean} [params.verify=true] - Whether to verify shares before reconstruction
   * @returns {Promise<BigNumber>} Reconstructed secret
   */
  async reconstructSecret({ shares, scheme, verify = true }) {
    try {
      // Input validation
      if (!Array.isArray(shares) || shares.length === 0) {
        throw new Error('Shares array is required');
      }

      // Verify shares if enabled and requested
      if (verify && this.enableVerifiableSharing) {
        const verificationResult = await this._verifyShares(shares);
        if (!verificationResult.valid) {
          throw new Error(`Share verification failed: ${verificationResult.reason}`);
        }
      }

      // Determine the scheme to use for reconstruction
      const selectedScheme = scheme || shares[0].scheme || this.defaultScheme;

      // Reconstruct the secret based on the scheme
      let secret;
      switch (selectedScheme) {
        case SecretSharingScheme.SHAMIR:
          secret = this._reconstructShamir(shares);
          break;
        case SecretSharingScheme.ADDITIVE:
          secret = this._reconstructAdditive(shares);
          break;
        case SecretSharingScheme.REPLICATED:
          secret = this._reconstructReplicated(shares);
          break;
        case SecretSharingScheme.HYBRID:
          secret = this._reconstructHybrid(shares);
          break;
        default:
          throw new Error(`Unsupported secret sharing scheme: ${selectedScheme}`);
      }

      logger.info(`Secret successfully reconstructed using ${selectedScheme} scheme`);
      return secret;
    } catch (error) {
      logger.error('Secret reconstruction failed:', error);
      throw new Error(`Secret reconstruction failed: ${error.message}`);
    }
  }

  /**
   * Add two secret shared values
   * @param {Array<Object>} sharesA - Shares of first value
   * @param {Array<Object>} sharesB - Shares of second value
   * @returns {Array<Object>} Shares of the sum
   */
  addShares(sharesA, sharesB) {
    try {
      // Input validation
      if (!Array.isArray(sharesA) || !Array.isArray(sharesB)) {
        throw new Error('Both share arrays are required');
      }
      if (sharesA.length !== sharesB.length) {
        throw new Error('Share arrays must have the same length');
      }
      if (sharesA[0].scheme !== sharesB[0].scheme) {
        throw new Error('Cannot add shares from different schemes');
      }

      const scheme = sharesA[0].scheme || this.defaultScheme;

      // Perform share-wise addition
      const sumShares = sharesA.map((shareA, index) => {
        const shareB = sharesB[index];
        const valueA = BigNumber.from(shareA.value);
        const valueB = BigNumber.from(shareB.value);
        const sumValue = valueA.add(valueB).mod(this.fieldPrime);

        return {
          ...shareA,
          value: sumValue.toString(),
          metadata: { ...shareA.metadata, operation: 'addition' }
        };
      });

      logger.info(`Shares successfully added using ${scheme} scheme`);
      return sumShares;
    } catch (error) {
      logger.error('Share addition failed:', error);
      throw new Error(`Share addition failed: ${error.message}`);
    }
  }

  /**
   * Multiply a secret shared value by a constant
   * @param {Array<Object>} shares - Shares of the value
   * @param {number|string|BigNumber} constant - Constant to multiply by
   * @returns {Array<Object>} Shares of the product
   */
  multiplyByConstant(shares, constant) {
    try {
      // Input validation
      if (!Array.isArray(shares) || shares.length === 0) {
        throw new Error('Shares array is required');
      }
      if (constant === undefined || constant === null) {
        throw new Error('Constant is required');
      }

      // Convert constant to BigNumber
      const constantValue = BigNumber.isBigNumber(constant)
        ? constant
        : BigNumber.from(constant.toString());

      // Perform multiplication on each share
      const productShares = shares.map(share => {
        const value = BigNumber.from(share.value);
        const productValue = value.mul(constantValue).mod(this.fieldPrime);

        return {
          ...share,
          value: productValue.toString(),
          metadata: { ...share.metadata, operation: 'constant_multiplication' }
        };
      });

      logger.info(`Shares successfully multiplied by constant using ${shares[0].scheme} scheme`);
      return productShares;
    } catch (error) {
      logger.error('Constant multiplication failed:', error);
      throw new Error(`Constant multiplication failed: ${error.message}`);
    }
  }

  /**
   * Convert a value to a field element
   * @param {string|number|BigNumber} value - Value to convert
   * @returns {BigNumber} Field element
   * @private
   */
  _toFieldElement(value) {
    try {
      const bnValue = BigNumber.isBigNumber(value)
        ? value
        : BigNumber.from(value.toString());
      return bnValue.mod(this.fieldPrime);
    } catch (error) {
      logger.error('Field element conversion failed:', error);
      throw new Error(`Field element conversion failed: ${error.message}`);
    }
  }

  /**
   * Implement Shamir's Secret Sharing scheme
   * @param {BigNumber} secret - Secret to share
   * @param {number} numShares - Number of shares to create
   * @param {number} threshold - Minimum shares needed for reconstruction
   * @returns {Array<Object>} Generated shares
   * @private
   */
  _shamir(secret, numShares, threshold) {
    const s = this._toFieldElement(secret);

    // Generate random polynomial coefficients
    const coefficients = [s];
    for (let i = 1; i < threshold; i++) {
      coefficients.push(this._generateRandomCoefficient());
    }

    // Generate shares by evaluating the polynomial at distinct points
    const shares = [];
    for (let i = 1; i <= numShares; i++) {
      const x = BigNumber.from(i);
      let y = BigNumber.from(0);
      let xPow = BigNumber.from(1);

      for (let j = 0; j < threshold; j++) {
        y = y.add(coefficients[j].mul(xPow)).mod(this.fieldPrime);
        xPow = xPow.mul(x).mod(this.fieldPrime);
      }

      shares.push({
        index: i,
        x: x.toString(),
        value: y.toString(),
        scheme: SecretSharingScheme.SHAMIR
      });
    }

    return shares;
  }

  /**
   * Implement Additive Secret Sharing scheme
   * @param {BigNumber} secret - Secret to share
   * @param {number} numShares - Number of shares to create
   * @param {number} threshold - Minimum shares needed for reconstruction (must be numShares)
   * @returns {Array<Object>} Generated shares
   * @private
   */
  _additive(secret, numShares, threshold) {
    if (threshold !== numShares) {
      logger.warn(`Additive sharing requires threshold = numShares, adjusting threshold from ${threshold} to ${numShares}`);
      threshold = numShares;
    }

    const s = this._toFieldElement(secret);
    const shares = [];
    let sumOfShares = BigNumber.from(0);

    // Generate random shares for all but the last party
    for (let i = 1; i < numShares; i++) {
      const value = this._generateRandomCoefficient();
      sumOfShares = sumOfShares.add(value).mod(this.fieldPrime);
      shares.push({
        index: i,
        value: value.toString(),
        scheme: SecretSharingScheme.ADDITIVE
      });
    }

    // Last share ensures the sum equals the secret
    const lastShare = s.sub(sumOfShares).mod(this.fieldPrime);
    shares.push({
      index: numShares,
      value: lastShare.toString(),
      scheme: SecretSharingScheme.ADDITIVE
    });

    return shares;
  }

  /**
   * Implement Replicated Secret Sharing scheme
   * @param {BigNumber} secret - Secret to share
   * @param {number} numShares - Number of shares to create
   * @param {number} threshold - Minimum shares needed for reconstruction
   * @returns {Array<Object>} Generated shares
   * @private
   */
  _replicated(secret, numShares, threshold) {
    const s = this._toFieldElement(secret);

    // Generate additive shares first
    const additiveShares = [];
    let sumOfShares = BigNumber.from(0);
    for (let i = 1; i < threshold; i++) {
      const value = this._generateRandomCoefficient();
      sumOfShares = sumOfShares.add(value).mod(this.fieldPrime);
      additiveShares.push({ index: i, value: value.toString() });
    }
    const lastAdditiveShare = s.sub(sumOfShares).mod(this.fieldPrime);
    additiveShares.push({ index: threshold, value: lastAdditiveShare.toString() });

    // Distribute subsets of additive shares to each party
    const shares = [];
    for (let i = 1; i <= numShares; i++) {
      const excludeIndex = ((i - 1) % threshold) + 1;
      const partyShares = additiveShares.filter(share => share.index !== excludeIndex);

      shares.push({
        index: i,
        value: JSON.stringify(partyShares),
        additiveShares: partyShares,
        scheme: SecretSharingScheme.REPLICATED
      });
    }

    return shares;
  }

  /**
   * Implement Hybrid Secret Sharing scheme
   * @param {BigNumber} secret - Secret to share
   * @param {number} numShares - Number of shares to create
   * @param {number} threshold - Minimum shares needed for reconstruction
   * @returns {Array<Object>} Generated shares
   * @private
   */
  _hybrid(secret, numShares, threshold) {
    // Choose scheme based on parameters
    if (numShares <= 10) {
      logger.info('Hybrid: Using Shamir for small number of shares');
      return this._shamir(secret, numShares, threshold);
    }
    if (threshold === numShares) {
      logger.info('Hybrid: Using Additive as threshold equals numShares');
      return this._additive(secret, numShares, threshold);
    }
    if (threshold === 2) {
      logger.info('Hybrid: Using Bivariate for threshold 2');
      return this._bivariateSharing(secret, numShares);
    }
    logger.info('Hybrid: Defaulting to Shamir');
    return this._shamir(secret, numShares, threshold);
  }

  /**
   * Implement specialized bivariate sharing for threshold t=2
   * @param {BigNumber} secret - Secret to share
   * @param {number} numShares - Number of shares to create
   * @returns {Array<Object>} Generated shares
   * @private
   */
  _bivariateSharing(secret, numShares) {
    const s = this._toFieldElement(secret);
    const shares = [];

    for (let i = 1; i <= numShares; i++) {
      const value1 = this._generateRandomCoefficient();
      const value2 = s.sub(value1).mod(this.fieldPrime);

      shares.push({
        index: i,
        value: JSON.stringify({ v1: value1.toString(), v2: value2.toString() }),
        bivariateComponents: { v1: value1.toString(), v2: value2.toString() },
        scheme: SecretSharingScheme.HYBRID
      });
    }

    return shares;
  }

  /**
   * Reconstruct a secret using Shamir's scheme
   * @param {Array<Object>} shares - Shares to reconstruct from
   * @returns {BigNumber} Reconstructed secret
   * @private
   */
  _reconstructShamir(shares) {
    if (shares.length < shares[0].threshold) {
      throw new Error(`At least ${shares[0].threshold} shares are required for Shamir reconstruction`);
    }

    let secret = BigNumber.from(0);
    for (let i = 0; i < shares.length; i++) {
      const xi = BigNumber.from(shares[i].x);
      const yi = BigNumber.from(shares[i].value);
      let lagrange = BigNumber.from(1);

      for (let j = 0; j < shares.length; j++) {
        if (i !== j) {
          const xj = BigNumber.from(shares[j].x);
          const numerator = xj;
          const denominator = xj.sub(xi).mod(this.fieldPrime);
          const inverse = denominator.modPow(this.fieldPrime.sub(2), this.fieldPrime);
          lagrange = lagrange.mul(numerator).mul(inverse).mod(this.fieldPrime);
        }
      }

      secret = secret.add(yi.mul(lagrange)).mod(this.fieldPrime);
    }

    return secret;
  }

  /**
   * Reconstruct a secret using Additive scheme
   * @param {Array<Object>} shares - Shares to reconstruct from
   * @returns {BigNumber} Reconstructed secret
   * @private
   */
  _reconstructAdditive(shares) {
    if (shares.length < shares[0].threshold) {
      throw new Error(`All ${shares[0].threshold} shares are required for Additive reconstruction`);
    }

    let sum = BigNumber.from(0);
    for (const share of shares) {
      sum = sum.add(BigNumber.from(share.value)).mod(this.fieldPrime);
    }

    return sum;
  }

  /**
   * Reconstruct a secret using Replicated scheme
   * @param {Array<Object>} shares - Shares to reconstruct from
   * @returns {BigNumber} Reconstructed secret
   * @private
   */
  _reconstructReplicated(shares) {
    const additiveShares = new Map();
    for (const share of shares) {
      const components = share.additiveShares || JSON.parse(share.value);
      for (const component of components) {
        additiveShares.set(component.index, BigNumber.from(component.value));
      }
    }

    if (additiveShares.size < shares[0].threshold) {
      throw new Error(`Not enough unique additive shares: found ${additiveShares.size}, need ${shares[0].threshold}`);
    }

    let sum = BigNumber.from(0);
    for (const value of additiveShares.values()) {
      sum = sum.add(value).mod(this.fieldPrime);
    }

    return sum;
  }

  /**
   * Reconstruct a secret using Hybrid scheme
   * @param {Array<Object>} shares - Shares to reconstruct from
   * @returns {BigNumber} Reconstructed secret
   * @private
   */
  _reconstructHybrid(shares) {
    if (shares[0].bivariateComponents || shares[0].value.includes('v1')) {
      return this._reconstructBivariate(shares);
    }
    return this._reconstructShamir(shares);
  }

  /**
   * Reconstruct a secret using bivariate sharing
   * @param {Array<Object>} shares - Shares to reconstruct from
   * @returns {BigNumber} Reconstructed secret
   * @private
   */
  _reconstructBivariate(shares) {
    if (shares.length < 2) {
      throw new Error('At least 2 shares are required for bivariate reconstruction');
    }

    const comp1 = shares[0].bivariateComponents || JSON.parse(shares[0].value);
    const comp2 = shares[1].bivariateComponents || JSON.parse(shares[1].value);
    const v1 = BigNumber.from(comp1.v1);
    const v2 = BigNumber.from(comp2.v2);

    return v1.add(v2).mod(this.fieldPrime);
  }

  /**
   * Generate a random coefficient for polynomial
   * @returns {BigNumber} Random coefficient
   * @private
   */
  _generateRandomCoefficient() {
    return randomFieldElement(256);
  }

  /**
   * Enhance shares with additional metadata and verification information
   * @param {Array<Object>} shares - Shares to enhance
   * @param {Object} options - Enhancement options
   * @returns {Array<Object>} Enhanced shares
   * @private
   */
  _enhanceShares(shares, options) {
    const { scheme, threshold, metadata, verifiable } = options;

    return shares.map(share => {
      const enhancedShare = {
        ...share,
        threshold,
        scheme,
        metadata: { ...metadata, createdAt: Date.now() }
      };

      if (verifiable) {
        enhancedShare.verification = this._generateVerificationCommitment(share);
      }

      return enhancedShare;
    });
  }

  /**
   * Generate verification commitment for a share
   * @param {Object} share - Share to create commitment for
   * @returns {Object} Verification commitment
   * @private
   */
  _generateVerificationCommitment(share) {
    const value = BigNumber.from(share.value);
    const salt = randomFieldElement(128);
    const commitment = crypto
      .createHash('sha256')
      .update(`${value.toString()}-${salt.toString()}`)
      .digest('hex');

    return { commitment, salt: salt.toString(), algorithm: 'sha256' };
  }

  /**
   * Verify shares before reconstruction
   * @param {Array<Object>} shares - Shares to verify
   * @returns {Object} Verification result
   * @private
   */
  async _verifyShares(shares) {
    if (!shares[0].verification) {
      return { valid: true, message: 'No verification data available' };
    }

    for (const share of shares) {
      const value = BigNumber.from(share.value);
      const { commitment, salt, algorithm } = share.verification;
      const calculatedCommitment = crypto
        .createHash(algorithm || 'sha256')
        .update(`${value.toString()}-${salt}`)
        .digest('hex');

      if (calculatedCommitment !== commitment) {
        return {
          valid: false,
          reason: `Share ${share.index} verification failed: commitment mismatch`
        };
      }
    }

    return { valid: true, message: 'All shares verified successfully' };
  }
}

module.exports = {
  SecretSharing,
  SecretSharingScheme
};
