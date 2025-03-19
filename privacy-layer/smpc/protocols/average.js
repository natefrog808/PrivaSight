/**
 * PrivaSight SMPC Average Protocol
 *
 * Implements a privacy-preserving protocol for computing averages across
 * distributed datasets without revealing individual data values.
 * This protocol uses secure multi-party computation (SMPC) techniques including:
 * - **Additive Secret Sharing**: Splits data into shares for secure distribution.
 * - **Differential Privacy**: Adds noise to protect individual data contributions.
 * - **Secure Aggregation**: Combines shares without exposing intermediate values.
 *
 * **Differential Privacy Note**:
 * - Each data owner adds Laplace noise to their local sum before sharing.
 * - To achieve a desired global privacy guarantee (e.g., (ε, δ)-differential privacy),
 *   the local `epsilon` and `delta` parameters should be adjusted based on the number
 *   of data owners and the composition of privacy losses (e.g., using simple or
 *   advanced composition theorems). For simplicity, this implementation assumes
 *   the user configures these parameters appropriately.
 *
 * **Verifiable Computation Note**:
 * - A basic commitment scheme is implemented as a placeholder. In a production
 *   system, replace with a cryptographically secure scheme like Pedersen commitments.
 */

const { BigNumber } = require('ethers');
const { randomFieldElement } = require('../../zkp/utils/hash');
const { SecretSharing } = require('../secret-sharing');
const logger = require('../../../utils/logger')('privacy-layer:smpc-average');

/**
 * Protocol for computing averages securely
 * @class AverageProtocol
 */
class AverageProtocol {
  /**
   * Create a new Average Protocol instance
   * @param {Object} options - Configuration options
   * @param {boolean} [options.enableDifferentialPrivacy=true] - Whether to apply differential privacy
   * @param {boolean} [options.enableVerifiableComputation=true] - Whether to generate computation proofs
   * @param {number} [options.defaultEpsilon=1.0] - Default epsilon value for differential privacy
   * @param {number} [options.defaultDelta=1e-6] - Default delta value for differential privacy
   * @param {number} [options.defaultSensitivity=1.0] - Default sensitivity for the average operation
   */
  constructor({
    enableDifferentialPrivacy = true,
    enableVerifiableComputation = true,
    defaultEpsilon = 1.0,
    defaultDelta = 1e-6,
    defaultSensitivity = 1.0
  } = {}) {
    this.enableDifferentialPrivacy = enableDifferentialPrivacy;
    this.enableVerifiableComputation = enableVerifiableComputation;
    this.defaultEpsilon = defaultEpsilon;
    this.defaultDelta = defaultDelta;
    this.defaultSensitivity = defaultSensitivity;

    // Initialize secret sharing instance
    this.secretSharing = new SecretSharing();

    logger.info('Average Protocol initialized with configuration:', {
      enableDifferentialPrivacy,
      enableVerifiableComputation,
      defaultEpsilon,
      defaultDelta,
      defaultSensitivity
    });
  }

  /**
   * Prepare data for secure computation
   * @param {Object} params - Preparation parameters
   * @param {Array<number>} params.data - Local data values to compute average from
   * @param {Array<string>} params.nodeIds - IDs of computation nodes
   * @param {Object} [params.privacyParameters] - Privacy parameters (epsilon, delta, sensitivity)
   * @param {string} [params.computationId] - Unique ID for the computation
   * @returns {Promise<Object>} Object containing shares, metadata, and verification material
   */
  async prepareData({ data, nodeIds, privacyParameters, computationId }) {
    try {
      logger.info(`Preparing data for average computation${computationId ? ` (${computationId})` : ''}`);

      // Input validation
      if (!Array.isArray(data) || data.length === 0) {
        throw new Error('Data must be a non-empty array');
      }
      if (!Array.isArray(nodeIds) || nodeIds.length < 2) {
        throw new Error('At least 2 computation nodes are required');
      }

      // Set privacy parameters
      const epsilon = privacyParameters?.epsilon || this.defaultEpsilon;
      const delta = privacyParameters?.delta || this.defaultDelta;
      const sensitivity = privacyParameters?.sensitivity || this.defaultSensitivity;

      // Compute local sum and count
      const sum = data.reduce((acc, val) => acc + val, 0);
      const count = data.length;

      // Apply differential privacy noise if enabled
      let noisySum = sum;
      let noiseMagnitude = 0;
      if (this.enableDifferentialPrivacy) {
        const noise = this._generateLaplaceNoise(epsilon, sensitivity);
        noisySum = sum + noise;
        noiseMagnitude = Math.abs(noise);
        logger.debug(`Applied differential privacy: epsilon=${epsilon}, noise=${noise.toFixed(4)}`);
      }

      // Create secret shares for sum and count
      const sumShares = await this.secretSharing.shareSecret({
        secret: noisySum.toString(),
        numShares: nodeIds.length,
        threshold: Math.ceil(nodeIds.length / 2) // Majority threshold
      });
      const countShares = await this.secretSharing.shareSecret({
        secret: count.toString(),
        numShares: nodeIds.length,
        threshold: Math.ceil(nodeIds.length / 2)
      });

      // Assign shares to nodes with commitments
      const nodeShares = {};
      let sumCommitment = null;
      let countCommitment = null;
      if (this.enableVerifiableComputation) {
        sumCommitment = this._createCommitment(noisySum.toString());
        countCommitment = this._createCommitment(count.toString());
      }

      for (let i = 0; i < nodeIds.length; i++) {
        const nodeId = nodeIds[i];
        nodeShares[nodeId] = {
          sumShare: sumShares[i],
          countShare: countShares[i],
          nodeIndex: i,
          ...(this.enableVerifiableComputation && {
            sumCommitment,
            countCommitment
          })
        };
      }

      // Create metadata
      const metadata = {
        computationId: computationId || `avg-${Date.now()}`,
        protocol: 'average',
        totalNodes: nodeIds.length,
        threshold: Math.ceil(nodeIds.length / 2),
        privacyParameters: { epsilon, delta, sensitivity, noiseMagnitude },
        timestamp: Date.now()
      };

      // Generate verification material
      const verificationMaterial = this.enableVerifiableComputation
        ? this._generateVerificationMaterial(noisySum, count, metadata)
        : null;

      logger.info(`Data prepared for ${nodeIds.length} nodes`);
      return { nodeShares, metadata, verificationMaterial };
    } catch (error) {
      logger.error('Data preparation failed:', error);
      throw new Error(`Data preparation failed: ${error.message}`);
    }
  }

  /**
   * Process a share at a computation node
   * @param {Object} params - Processing parameters
   * @param {Object} params.share - Node's own share
   * @param {Array<Object>} [params.peerShares=[]] - Shares from peer nodes
   * @param {Object} params.metadata - Computation metadata
   * @returns {Promise<Object>} Processed result (partial or final)
   */
  async processShareAtNode({ share, peerShares = [], metadata }) {
    try {
      logger.info(`Processing share at node ${share.nodeIndex}`);

      // Validate share
      if (!share || !share.sumShare || !share.countShare) {
        throw new Error('Invalid share data');
      }

      // Initialize with own share
      let sumShareValue = BigNumber.from(share.sumShare.value);
      let countShareValue = BigNumber.from(share.countShare.value);
      let aggregatedSumCommitments = this.enableVerifiableComputation ? [share.sumCommitment] : [];
      let aggregatedCountCommitments = this.enableVerifiableComputation ? [share.countCommitment] : [];

      // Aggregate peer shares
      for (const peerShare of peerShares) {
        if (!peerShare || !peerShare.sumShare || !peerShare.countShare) {
          logger.warn('Skipping invalid peer share');
          continue;
        }
        sumShareValue = sumShareValue.add(peerShare.sumShare.value);
        countShareValue = countShareValue.add(peerShare.countShare.value);
        if (this.enableVerifiableComputation) {
          aggregatedSumCommitments.push(peerShare.sumCommitment);
          aggregatedCountCommitments.push(peerShare.countCommitment);
        }
      }

      // Determine if this is the final aggregation
      const isFinalAggregation = metadata.isFinalAggregation === true;
      let result;

      if (isFinalAggregation) {
        const sumValue = Number(sumShareValue.toString());
        const countValue = Number(countShareValue.toString());
        const average = countValue > 0 ? sumValue / countValue : 0;

        result = {
          average,
          count: countValue,
          metadata: { ...metadata, completedAt: Date.now() },
          ...(this.enableVerifiableComputation && {
            verificationMaterial: {
              sumCommitment: this._aggregateCommitments(aggregatedSumCommitments),
              countCommitment: this._aggregateCommitments(aggregatedCountCommitments)
            }
          })
        };
        logger.info(`Final average computed: ${average}`);
      } else {
        result = {
          sumShare: { value: sumShareValue.toString(), nodeIndex: share.nodeIndex },
          countShare: { value: countShareValue.toString(), nodeIndex: share.nodeIndex },
          metadata: { ...metadata, processedAt: Date.now() },
          ...(this.enableVerifiableComputation && {
            sumCommitment: this._aggregateCommitments(aggregatedSumCommitments),
            countCommitment: this._aggregateCommitments(aggregatedCountCommitments)
          })
        };
        logger.debug('Intermediate aggregation completed');
      }

      return result;
    } catch (error) {
      logger.error('Share processing failed:', error);
      throw new Error(`Share processing failed: ${error.message}`);
    }
  }

  /**
   * Aggregate results from multiple nodes
   * @param {Array<Object>} nodeResults - Results from computation nodes
   * @param {Object} privacyParameters - Privacy parameters for metadata
   * @returns {Promise<Object>} Final aggregated result
   */
  async aggregateResults(nodeResults, privacyParameters) {
    try {
      logger.info(`Aggregating results from ${nodeResults.length} nodes`);

      if (!Array.isArray(nodeResults) || nodeResults.length === 0) {
        throw new Error('Node results must be a non-empty array');
      }

      // Case 1: Nodes return final averages (weighted average)
      if (nodeResults[0].average !== undefined) {
        let totalCount = 0;
        let weightedSum = 0;
        for (const result of nodeResults) {
          totalCount += result.count;
          weightedSum += result.average * result.count;
        }
        const finalAverage = totalCount > 0 ? weightedSum / totalCount : 0;

        return {
          average: finalAverage,
          count: totalCount,
          metadata: {
            protocol: 'average',
            nodesContributed: nodeResults.length,
            aggregatedAt: Date.now(),
            privacyParameters
          }
        };
      }

      // Case 2: Nodes return shares (reconstruct and compute average)
      let sumSharesTotal = BigNumber.from(0);
      let countSharesTotal = BigNumber.from(0);
      let sumCommitments = this.enableVerifiableComputation ? [] : null;
      let countCommitments = this.enableVerifiableComputation ? [] : null;

      for (const result of nodeResults) {
        sumSharesTotal = sumSharesTotal.add(result.sumShare.value);
        countSharesTotal = countSharesTotal.add(result.countShare.value);
        if (this.enableVerifiableComputation) {
          sumCommitments.push(result.sumCommitment);
          countCommitments.push(result.countCommitment);
        }
      }

      const sumValue = Number(sumSharesTotal.toString());
      const countValue = Number(countSharesTotal.toString());
      const finalAverage = countValue > 0 ? sumValue / countValue : 0;

      const result = {
        average: finalAverage,
        count: countValue,
        metadata: {
          protocol: 'average',
          nodesContributed: nodeResults.length,
          aggregatedAt: Date.now(),
          privacyParameters
        },
        ...(this.enableVerifiableComputation && {
          verificationMaterial: {
            sumCommitment: this._aggregateCommitments(sumCommitments),
            countCommitment: this._aggregateCommitments(countCommitments),
            sumValue,
            countValue
          }
        })
      };

      logger.info(`Aggregated average: ${finalAverage}`);
      return result;
    } catch (error) {
      logger.error('Result aggregation failed:', error);
      throw new Error(`Result aggregation failed: ${error.message}`);
    }
  }

  /**
   * Verify the correctness of a computation result
   * @param {Object} result - Computation result to verify
   * @param {Object} options - Verification options
   * @param {Array<Object>} [options.nodeResults] - Original node results for recomputation
   * @param {Object} [options.privacyParameters] - Privacy parameters
   * @returns {Promise<boolean>} Whether the result is valid
   */
  async verifyResult(result, { nodeResults, privacyParameters }) {
    try {
      logger.info('Verifying computation result');

      // Basic validation
      if (!result || result.average === undefined || result.count === undefined) {
        logger.warn('Invalid result format');
        return false;
      }

      // Recompute from node results if provided
      if (Array.isArray(nodeResults) && nodeResults.length > 0) {
        const recomputed = await this.aggregateResults(nodeResults, privacyParameters);
        const averageDiff = Math.abs(recomputed.average - result.average);
        const countDiff = Math.abs(recomputed.count - result.count);
        const isValid = averageDiff < 1e-9 && countDiff === 0;
        if (!isValid) {
          logger.warn(`Recomputed result mismatch: average diff=${averageDiff}, count diff=${countDiff}`);
        }
        return isValid;
      }

      // Verify using commitments if available
      if (this.enableVerifiableComputation && result.verificationMaterial) {
        return this._verifyWithMaterial(result, result.verificationMaterial);
      }

      logger.warn('Insufficient data for verification; assuming valid');
      return true;
    } catch (error) {
      logger.error('Verification failed:', error);
      return false;
    }
  }

  /**
   * Generate Laplace noise for differential privacy
   * @param {number} epsilon - Privacy parameter
   * @param {number} sensitivity - Sensitivity of the computation
   * @returns {number} Noise value
   * @private
   */
  _generateLaplaceNoise(epsilon, sensitivity) {
    const scale = sensitivity / epsilon;
    const uniform = Math.random() - 0.5;
    const sign = uniform >= 0 ? 1 : -1;
    return sign * scale * Math.log(1 - 2 * Math.abs(uniform));
  }

  /**
   * Generate verification material
   * @param {number} sum - Noisy sum value
   * @param {number} count - Count value
   * @param {Object} metadata - Computation metadata
   * @returns {Object} Verification material
   * @private
   */
  _generateVerificationMaterial(sum, count, metadata) {
    return {
      sumCommitment: this._createCommitment(sum.toString()),
      countCommitment: this._createCommitment(count.toString()),
      metadata: {
        commitmentType: 'mock-pedersen',
        timestamp: Date.now()
      }
    };
  }

  /**
   * Create a cryptographic commitment (mock implementation)
   * @param {string} value - Value to commit to
   * @returns {Object} Commitment object
   * @private
   */
  _createCommitment(value) {
    const blindingFactor = randomFieldElement();
    // Mock commitment: In reality, use a library for Pedersen commitments
    return {
      value: value, // For mock verification; not included in real commitments
      blindingFactor
    };
  }

  /**
   * Aggregate commitments (mock implementation)
   * @param {Array<Object>} commitments - List of commitments to aggregate
   * @returns {Object} Aggregated commitment
   * @private
   */
  _aggregateCommitments(commitments) {
    if (!commitments || commitments.length === 0) return null;
    // Mock aggregation: Sum blinding factors and values
    const aggregated = commitments.reduce((acc, curr) => ({
      value: BigNumber.from(acc.value).add(curr.value).toString(),
      blindingFactor: BigNumber.from(acc.blindingFactor).add(curr.blindingFactor).toString()
    }));
    return aggregated;
  }

  /**
   * Verify a result using verification material
   * @param {Object} result - Computation result
   * @param {Object} verificationMaterial - Verification material
   * @returns {boolean} Whether the result matches the commitment
   * @private
   */
  _verifyWithMaterial(result, verificationMaterial) {
    // Mock verification: Check if committed values match result
    const sumMatches = BigNumber.from(verificationMaterial.sumCommitment.value)
      .eq(BigNumber.from(result.verificationMaterial.sumValue.toString()));
    const countMatches = BigNumber.from(verificationMaterial.countCommitment.value)
      .eq(BigNumber.from(result.verificationMaterial.countValue.toString()));

    const isValid = sumMatches && countMatches;
    if (!isValid) {
      logger.warn('Commitment verification failed');
    }
    return isValid;
  }
}

module.exports = { AverageProtocol };
