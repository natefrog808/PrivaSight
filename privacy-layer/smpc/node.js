/**
 * PrivaSight SMPC Node Implementation
 *
 * This module implements a secure multi-party computation node that participates in
 * privacy-preserving distributed computations. Each node maintains its own private state,
 * processes computation requests, and communicates with other nodes while preserving data privacy.
 */

const EventEmitter = require('events');
const { BigNumber } = require('ethers');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const { randomFieldElement, poseidonHashSync } = require('../zkp/utils/hash');
const { SecretSharing } = require('../secret-sharing');
const logger = require('../../utils/logger')('privacy-layer:smpc-node');

// Node state constants
const NodeState = {
  IDLE: 'idle',
  INITIALIZING: 'initializing',
  WAITING_FOR_PEERS: 'waiting_for_peers',
  PROCESSING: 'processing',
  SHARING: 'sharing',
  COMPUTING: 'computing',
  AGGREGATING: 'aggregating',
  VERIFYING: 'verifying',
  ERROR: 'error'
};

// Statistical operation types for StatisticalProtocol
const OPERATION_TYPES = {
  MEAN: 'mean',
  VARIANCE: 'variance',
  STANDARD_DEVIATION: 'std_dev',
  CORRELATION: 'correlation',
  COVARIANCE: 'covariance',
  PERCENTILE: 'percentile',
  MIN: 'min',
  MAX: 'max',
  MEDIAN: 'median',
  T_TEST: 't_test',
  CHI_SQUARE: 'chi_square',
  LINEAR_REGRESSION: 'linear_regression',
  HISTOGRAM: 'histogram'
};

/**
 * Protocol for computing averages securely
 * @class AverageProtocol
 */
class AverageProtocol {
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
    this.secretSharing = new SecretSharing();
    logger.info('Average Protocol initialized with configuration:', {
      enableDifferentialPrivacy,
      enableVerifiableComputation,
      defaultEpsilon,
      defaultDelta
    });
  }

  async prepareData({ data, nodeIds, privacyParameters, computationId }) {
    try {
      logger.info(`Preparing data for average computation${computationId ? ` (${computationId})` : ''}`);
      if (!Array.isArray(data) || data.length === 0) throw new Error('Data must be a non-empty array');
      if (!Array.isArray(nodeIds) || nodeIds.length < 2) throw new Error('At least 2 computation nodes are required');

      const epsilon = privacyParameters?.epsilon || this.defaultEpsilon;
      const delta = privacyParameters?.delta || this.defaultDelta;
      const sensitivity = privacyParameters?.sensitivity || this.defaultSensitivity;

      const sum = data.reduce((acc, val) => acc + val, 0);
      const count = data.length;

      let noisySum = sum;
      let noiseMagnitude = 0;
      if (this.enableDifferentialPrivacy) {
        const noise = this._generateLaplaceNoise(epsilon, sensitivity);
        noisySum = sum + noise;
        noiseMagnitude = Math.abs(noise);
        logger.debug(`Applied differential privacy with epsilon=${epsilon}, noise magnitude=${noiseMagnitude.toFixed(4)}`);
      }

      const sumShares = await this.secretSharing.shareSecret({
        secret: noisySum.toString(),
        numShares: nodeIds.length,
        threshold: Math.ceil(nodeIds.length / 2)
      });

      const countShares = await this.secretSharing.shareSecret({
        secret: count.toString(),
        numShares: nodeIds.length,
        threshold: Math.ceil(nodeIds.length / 2)
      });

      const nodeShares = {};
      for (let i = 0; i < nodeIds.length; i++) {
        const nodeId = nodeIds[i];
        nodeShares[nodeId] = {
          sumShare: sumShares[i],
          countShare: countShares[i],
          nodeIndex: i
        };
      }

      const metadata = {
        computationId: computationId || `avg-${Date.now()}`,
        protocol: 'average',
        totalNodes: nodeIds.length,
        threshold: Math.ceil(nodeIds.length / 2),
        privacyParameters: { epsilon, delta, sensitivity, noiseMagnitude },
        timestamp: Date.now()
      };

      let verificationMaterial = null;
      if (this.enableVerifiableComputation) {
        verificationMaterial = this._generateVerificationMaterial(noisySum, count, metadata);
      }

      logger.info(`Data prepared for average computation with ${nodeIds.length} nodes`);
      return { nodeShares, metadata, verificationMaterial };
    } catch (error) {
      logger.error('Failed to prepare data for average computation:', error);
      throw new Error(`Data preparation failed: ${error.message}`);
    }
  }

  async processShareAtNode({ share, peerShares = [], metadata }) {
    try {
      logger.info(`Processing share for average computation at node ${share.nodeIndex}`);
      if (!share || !share.sumShare || !share.countShare) throw new Error('Invalid share data');

      let sumShareValue = BigNumber.from(share.sumShare.value);
      let countShareValue = BigNumber.from(share.countShare.value);

      for (const peerShare of peerShares) {
        if (!peerShare || !peerShare.sumShare || !peerShare.countShare) {
          logger.warn('Skipping invalid peer share');
          continue;
        }
        sumShareValue = sumShareValue.add(peerShare.sumShare.value);
        countShareValue = countShareValue.add(peerShare.countShare.value);
      }

      const isFinalAggregation = metadata.isFinalAggregation === true;
      let result;
      if (isFinalAggregation) {
        const sumValue = Number(sumShareValue.toString());
        const countValue = Number(countShareValue.toString());
        const average = countValue > 0 ? sumValue / countValue : 0;
        result = {
          average,
          count: countValue,
          metadata: { ...metadata, completedAt: Date.now() }
        };
        logger.info(`Final average computed: ${average}`);
      } else {
        result = {
          sumShare: { value: sumShareValue.toString(), nodeIndex: share.nodeIndex },
          countShare: { value: countShareValue.toString(), nodeIndex: share.nodeIndex },
          metadata: { ...metadata, processedAt: Date.now() }
        };
        logger.debug('Processed share for intermediate aggregation');
      }
      return result;
    } catch (error) {
      logger.error('Failed to process share at node:', error);
      throw new Error(`Share processing failed: ${error.message}`);
    }
  }

  async aggregateResults(nodeResults, privacyParameters) {
    try {
      logger.info(`Aggregating average results from ${nodeResults.length} nodes`);
      if (!Array.isArray(nodeResults) || nodeResults.length === 0) throw new Error('Node results must be a non-empty array');

      if (nodeResults[0].average !== undefined) {
        let totalCount = 0;
        let weightedSumOfAverages = 0;
        for (const result of nodeResults) {
          totalCount += result.count;
          weightedSumOfAverages += result.average * result.count;
        }
        const finalAverage = totalCount > 0 ? weightedSumOfAverages / totalCount : 0;
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

      let sumSharesTotal = BigNumber.from(0);
      let countSharesTotal = BigNumber.from(0);
      for (const result of nodeResults) {
        sumSharesTotal = sumSharesTotal.add(result.sumShare.value);
        countSharesTotal = countSharesTotal.add(result.countShare.value);
      }
      const sumValue = Number(sumSharesTotal.toString());
      const countValue = Number(countSharesTotal.toString());
      const finalAverage = countValue > 0 ? sumValue / countValue : 0;
      logger.info(`Final average computed from aggregated shares: ${finalAverage}`);
      return {
        average: finalAverage,
        count: countValue,
        metadata: {
          protocol: 'average',
          nodesContributed: nodeResults.length,
          aggregatedAt: Date.now(),
          privacyParameters
        }
      };
    } catch (error) {
      logger.error('Failed to aggregate results:', error);
      throw new Error(`Result aggregation failed: ${error.message}`);
    }
  }

  async verifyResult(result, { nodeResults, privacyParameters }) {
    try {
      logger.info('Verifying average computation result');
      if (!result || result.average === undefined || result.count === undefined) {
        logger.warn('Invalid result format');
        return false;
      }

      if (Array.isArray(nodeResults) && nodeResults.length > 0) {
        const recomputedResult = await this.aggregateResults(nodeResults, privacyParameters);
        const averageDiff = Math.abs(recomputedResult.average - result.average);
        const countDiff = Math.abs(recomputedResult.count - result.count);
        const isValid = averageDiff < 1e-9 && countDiff < 1e-9;
        if (!isValid) {
          logger.warn(`Result verification failed: average diff=${averageDiff}, count diff=${countDiff}`);
        }
        return isValid;
      }

      if (result.verificationMaterial) {
        return this._verifyWithMaterial(result, result.verificationMaterial);
      }

      logger.warn('Insufficient information for strong verification');
      return true;
    } catch (error) {
      logger.error('Failed to verify result:', error);
      return false;
    }
  }

  _generateLaplaceNoise(epsilon, sensitivity) {
    const scale = sensitivity / epsilon;
    const uniform = Math.random() - 0.5;
    const sign = uniform >= 0 ? 1 : -1;
    const noise = sign * scale * Math.log(1 - 2 * Math.abs(uniform));
    return noise;
  }

  _generateVerificationMaterial(sum, count, metadata) {
    const commitment = {
      sumCommitment: this._createCommitment(sum.toString()),
      countCommitment: this._createCommitment(count.toString()),
      metadata: {
        commitmentType: 'pedersen',
        timestamp: Date.now()
      }
    };
    return commitment;
  }

  _createCommitment(value) {
    const blindingFactor = randomFieldElement();
    const commitment = {
      committed: true,
      blindingFactor
    };
    return commitment;
  }

  _verifyWithMaterial(result, verificationMaterial) {
    return true; // Placeholder
  }
}

/**
 * Protocol for advanced statistical analysis with privacy preservation
 * @class StatisticalProtocol
 */
class StatisticalProtocol {
  constructor({
    enableDifferentialPrivacy = true,
    enableVerifiableComputation = true,
    defaultEpsilon = 1.0,
    defaultDelta = 1e-6,
    sensitivityConfig = {
      mean: 1.0,
      variance: 2.0,
      std_dev: 1.0,
      correlation: 2.0,
      covariance: 2.0,
      percentile: 1.0,
      min: 1.0,
      max: 1.0,
      median: 1.0,
      t_test: 2.0,
      chi_square: 2.0,
      linear_regression: 2.0,
      histogram: 1.0
    }
  } = {}) {
    this.enableDifferentialPrivacy = enableDifferentialPrivacy;
    this.enableVerifiableComputation = enableVerifiableComputation;
    this.defaultEpsilon = defaultEpsilon;
    this.defaultDelta = defaultDelta;
    this.sensitivityConfig = sensitivityConfig;
    this.secretSharing = new SecretSharing();
    logger.info('Statistical Protocol initialized with configuration:', {
      enableDifferentialPrivacy,
      enableVerifiableComputation,
      defaultEpsilon,
      defaultDelta
    });
  }

  async prepareData({ data, operation, operationParams = {}, nodeIds, privacyParameters, computationId }) {
    try {
      logger.info(`Preparing data for ${operation} computation${computationId ? ` (${computationId})` : ''}`);
      if (!Object.values(OPERATION_TYPES).includes(operation)) throw new Error(`Unsupported operation type: ${operation}`);
      if (!Array.isArray(data) || data.length === 0) throw new Error('Data must be a non-empty array');
      if (!Array.isArray(nodeIds) || nodeIds.length < 2) throw new Error('At least 2 computation nodes are required');

      const epsilon = privacyParameters?.epsilon || this.defaultEpsilon;
      const delta = privacyParameters?.delta || this.defaultDelta;
      const sensitivity = privacyParameters?.sensitivity || this.sensitivityConfig[operation] || 1.0;

      const { preparedData, operationMetadata } = await this._prepareOperationData(data, operation, operationParams);

      let noisyData = preparedData;
      let noiseMagnitudes = {};
      if (this.enableDifferentialPrivacy) {
        ({ noisyData, noiseMagnitudes } = this._applyDifferentialPrivacy(preparedData, operation, epsilon, sensitivity));
        logger.debug(`Applied differential privacy with epsilon=${epsilon}, operation=${operation}`);
      }

      const shares = {};
      for (const key of Object.keys(noisyData)) {
        const value = noisyData[key];
        const valueShares = await this.secretSharing.shareSecret({
          secret: typeof value === 'number' ? value.toString() : value,
          numShares: nodeIds.length,
          threshold: Math.ceil(nodeIds.length / 2)
        });
        shares[key] = valueShares;
      }

      const nodeShares = {};
      for (let i = 0; i < nodeIds.length; i++) {
        const nodeId = nodeIds[i];
        const nodeShare = { nodeIndex: i };
        for (const key of Object.keys(shares)) {
          nodeShare[key] = shares[key][i];
        }
        nodeShares[nodeId] = nodeShare;
      }

      const metadata = {
        computationId: computationId || `stat-${Date.now()}`,
        protocol: 'statistical',
        operation,
        operationParams,
        operationMetadata,
        totalNodes: nodeIds.length,
        threshold: Math.ceil(nodeIds.length / 2),
        privacyParameters: { epsilon, delta, sensitivity, noiseMagnitudes },
        dataKeys: Object.keys(noisyData),
        timestamp: Date.now()
      };

      let verificationMaterial = null;
      if (this.enableVerifiableComputation) {
        verificationMaterial = this._generateVerificationMaterial(noisyData, metadata);
      }

      logger.info(`Data prepared for ${operation} computation with ${nodeIds.length} nodes`);
      return { nodeShares, metadata, verificationMaterial };
    } catch (error) {
      logger.error(`Failed to prepare data for ${operation} computation:`, error);
      throw new Error(`Data preparation failed: ${error.message}`);
    }
  }

  async processShareAtNode({ share, peerShares = [], metadata }) {
    try {
      logger.info(`Processing share for ${metadata.operation} computation at node ${share.nodeIndex}`);
      if (!share || share.nodeIndex === undefined) throw new Error('Invalid share data');

      const isFinalAggregation = metadata.isFinalAggregation === true;
      const operation = metadata.operation;

      if (isFinalAggregation) {
        return this._processOperationFinalAggregation(share, peerShares, metadata);
      } else {
        return this._processOperationIntermediateAggregation(share, peerShares, metadata);
      }
    } catch (error) {
      logger.error(`Failed to process share at node for ${metadata.operation}:`, error);
      throw new Error(`Share processing failed: ${error.message}`);
    }
  }

  async aggregateResults(nodeResults, privacyParameters) {
    try {
      if (!Array.isArray(nodeResults) || nodeResults.length === 0) throw new Error('Node results must be a non-empty array');
      const operation = nodeResults[0].metadata?.operation || 'unknown';
      logger.info(`Aggregating ${operation} results from ${nodeResults.length} nodes`);

      if (nodeResults[0].result !== undefined) {
        return this._aggregateFinalResults(nodeResults, operation, privacyParameters);
      }

      const combinedShare = {
        nodeIndex: 0,
        metadata: nodeResults[0].metadata
      };
      const dataKeys = Object.keys(nodeResults[0]).filter(key => key !== 'nodeIndex' && key !== 'metadata');

      for (const key of dataKeys) {
        let combinedValue = BigNumber.from(0);
        for (const result of nodeResults) {
          combinedValue = combinedValue.add(BigNumber.from(result[key].value));
        }
        combinedShare[key] = { value: combinedValue.toString(), nodeIndex: 0 };
      }

      const updatedMetadata = { ...combinedShare.metadata, isFinalAggregation: true };
      return this.processShareAtNode({ share: combinedShare, peerShares: [], metadata: updatedMetadata });
    } catch (error) {
      logger.error('Failed to aggregate results:', error);
      throw new Error(`Result aggregation failed: ${error.message}`);
    }
  }

  async verifyResult(result, { nodeResults, privacyParameters }) {
    try {
      const operation = result.metadata?.operation || 'unknown';
      logger.info(`Verifying ${operation} computation result`);
      if (!result || result.result === undefined) {
        logger.warn('Invalid result format');
        return false;
      }

      if (Array.isArray(nodeResults) && nodeResults.length > 0) {
        const recomputedResult = await this.aggregateResults(nodeResults, privacyParameters);
        return this._compareResults(result, recomputedResult, operation);
      }

      if (this.enableVerifiableComputation && result.verificationMaterial) {
        return this._verifyWithMaterial(result, result.verificationMaterial);
      }

      logger.warn('Insufficient information for strong verification');
      return true;
    } catch (error) {
      logger.error('Failed to verify result:', error);
      return false;
    }
  }

  async _prepareOperationData(data, operation, operationParams) {
    const result = { preparedData: {}, operationMetadata: {} };
    const n = data.length;
    result.operationMetadata.sampleSize = n;

    switch (operation) {
      case OPERATION_TYPES.MEAN:
        result.preparedData.sum = data.reduce((acc, val) => acc + val, 0);
        result.preparedData.count = n;
        break;
      case OPERATION_TYPES.VARIANCE:
      case OPERATION_TYPES.STANDARD_DEVIATION:
        result.preparedData.sum = data.reduce((acc, val) => acc + val, 0);
        result.preparedData.sumOfSquares = data.reduce((acc, val) => acc + val * val, 0);
        result.preparedData.count = n;
        break;
      case OPERATION_TYPES.CORRELATION:
      case OPERATION_TYPES.COVARIANCE:
        if (!data.every(item => Array.isArray(item) && item.length === 2)) throw new Error(`${operation} requires paired data points [x, y]`);
        result.preparedData.sumX = data.reduce((acc, [x]) => acc + x, 0);
        result.preparedData.sumY = data.reduce((acc, [, y]) => acc + y, 0);
        result.preparedData.sumXY = data.reduce((acc, [x, y]) => acc + x * y, 0);
        result.preparedData.sumXSquared = data.reduce((acc, [x]) => acc + x * x, 0);
        result.preparedData.sumYSquared = data.reduce((acc, [, y]) => acc + y * y, 0);
        result.preparedData.count = n;
        break;
      case OPERATION_TYPES.PERCENTILE:
      case OPERATION_TYPES.MEDIAN:
        const percentile = operation === OPERATION_TYPES.MEDIAN ? 50 : operationParams.percentile;
        if (percentile === undefined || percentile < 0 || percentile > 100) throw new Error('Percentile must be between 0 and 100');
        const min = Math.min(...data);
        const max = Math.max(...data);
        const numBuckets = Math.min(50, Math.max(10, Math.ceil(n / 5)));
        const bucketSize = (max - min) / numBuckets;
        const histogram = Array(numBuckets).fill(0);
        for (const value of data) {
          const bucketIndex = Math.min(numBuckets - 1, Math.floor((value - min) / bucketSize));
          histogram[bucketIndex]++;
        }
        result.preparedData.histogram = histogram;
        result.preparedData.min = min;
        result.preparedData.max = max;
        result.preparedData.count = n;
        result.operationMetadata.numBuckets = numBuckets;
        result.operationMetadata.percentile = percentile;
        break;
      case OPERATION_TYPES.MIN:
        result.preparedData.min = Math.min(...data);
        break;
      case OPERATION_TYPES.MAX:
        result.preparedData.max = Math.max(...data);
        break;
      case OPERATION_TYPES.T_TEST:
        const testType = operationParams.testType || 'paired';
        result.operationMetadata.testType = testType;
        if (testType === 'paired') {
          if (!data.every(item => Array.isArray(item) && item.length === 2)) throw new Error('Paired t-test requires paired data points [x, y]');
          const differences = data.map(([x, y]) => x - y);
          result.preparedData.sumD = differences.reduce((acc, d) => acc + d, 0);
          result.preparedData.sumDSquared = differences.reduce((acc, d) => acc + d * d, 0);
          result.preparedData.count = n;
        } else if (testType === 'independent') {
          if (!operationParams.group1 || !operationParams.group2) throw new Error('Independent t-test requires two separate data groups');
          const group1 = operationParams.group1;
          const group2 = operationParams.group2;
          result.preparedData.sum1 = group1.reduce((acc, val) => acc + val, 0);
          result.preparedData.sumSquared1 = group1.reduce((acc, val) => acc + val * val, 0);
          result.preparedData.count1 = group1.length;
          result.preparedData.sum2 = group2.reduce((acc, val) => acc + val, 0);
          result.preparedData.sumSquared2 = group2.reduce((acc, val) => acc + val * val, 0);
          result.preparedData.count2 = group2.length;
        } else {
          throw new Error(`Unsupported t-test type: ${testType}`);
        }
        break;
      case OPERATION_TYPES.CHI_SQUARE:
        const observed = operationParams.observed || data;
        const expected = operationParams.expected;
        if (!expected) throw new Error('Chi-square test requires expected frequencies');
        const flatObserved = Array.isArray(observed[0]) ? observed.flat() : observed;
        const flatExpected = Array.isArray(expected[0]) ? expected.flat() : expected;
        if (flatObserved.length !== flatExpected.length) throw new Error('Observed and expected frequencies must have the same length');
        const components = flatObserved.map((o, i) => (o - flatExpected[i]) ** 2 / flatExpected[i]);
        result.preparedData.components = components;
        result.operationMetadata.degreesOfFreedom = components.length - 1;
        break;
      case OPERATION_TYPES.LINEAR_REGRESSION:
        if (!data.every(item => Array.isArray(item) && item.length === 2)) throw new Error('Linear regression requires paired data points [x, y]');
        result.preparedData.sumX = data.reduce((acc, [x]) => acc + x, 0);
        result.preparedData.sumY = data.reduce((acc, [, y]) => acc + y, 0);
        result.preparedData.sumXY = data.reduce((acc, [x, y]) => acc + x * y, 0);
        result.preparedData.sumXSquared = data.reduce((acc, [x]) => acc + x * x, 0);
        result.preparedData.count = n;
        break;
      case OPERATION_TYPES.HISTOGRAM:
        const numBuckets = operationParams.numBuckets || 10;
        const minValue = operationParams.min || Math.min(...data);
        const maxValue = operationParams.max || Math.max(...data);
        const bucketSize = (maxValue - minValue) / numBuckets;
        const histogram = Array(numBuckets).fill(0);
        for (const value of data) {
          const bucketIndex = Math.min(numBuckets - 1, Math.floor((value - minValue) / bucketSize));
          histogram[bucketIndex]++;
        }
        result.preparedData.histogram = histogram;
        result.preparedData.min = minValue;
        result.preparedData.max = maxValue;
        result.operationMetadata.numBuckets = numBuckets;
        result.operationMetadata.bucketSize = bucketSize;
        break;
      default:
        throw new Error(`Unsupported operation: ${operation}`);
    }
    return result;
  }

  _applyDifferentialPrivacy(preparedData, operation, epsilon, sensitivity) {
    const noisyData = { ...preparedData };
    const noiseMagnitudes = {};

    for (const key of Object.keys(preparedData)) {
      if (key === 'count' && [
        OPERATION_TYPES.MEAN,
        OPERATION_TYPES.VARIANCE,
        OPERATION_TYPES.STANDARD_DEVIATION,
        OPERATION_TYPES.CORRELATION,
        OPERATION_TYPES.COVARIANCE,
        OPERATION_TYPES.LINEAR_REGRESSION
      ].includes(operation)) continue;

      if (key === 'histogram') {
        const noisyHistogram = preparedData[key].map(count => {
          const noise = this._generateLaplaceNoise(epsilon, sensitivity);
          return Math.max(0, count + noise);
        });
        noisyData[key] = noisyHistogram;
        noiseMagnitudes[key] = noisyHistogram.map((val, i) => Math.abs(val - preparedData[key][i]));
      } else if (typeof preparedData[key] === 'number') {
        const noise = this._generateLaplaceNoise(epsilon, sensitivity);
        noisyData[key] = preparedData[key] + noise;
        noiseMagnitudes[key] = Math.abs(noise);
      }
    }
    return { noisyData, noiseMagnitudes };
  }

  _processOperationIntermediateAggregation(share, peerShares, metadata) {
    const result = { nodeIndex: share.nodeIndex, metadata };
    const dataKeys = Object.keys(share).filter(key => key !== 'nodeIndex' && key !== 'metadata');

    for (const key of dataKeys) {
      let aggregatedValue = BigNumber.from(share[key].value);
      for (const peerShare of peerShares) {
        if (peerShare[key]) aggregatedValue = aggregatedValue.add(BigNumber.from(peerShare[key].value));
      }
      result[key] = { value: aggregatedValue.toString(), nodeIndex: share.nodeIndex };
    }
    logger.debug(`Processed intermediate aggregation for ${metadata.operation}`);
    return result;
  }

  _processOperationFinalAggregation(share, peerShares, metadata) {
    const operation = metadata.operation;
    const dataKeys = Object.keys(share).filter(key => key !== 'nodeIndex' && key !== 'metadata');
    const dataValues = {};

    for (const key of dataKeys) {
      let aggregatedValue = BigNumber.from(share[key].value);
      for (const peerShare of peerShares) {
        if (peerShare[key]) aggregatedValue = aggregatedValue.add(BigNumber.from(peerShare[key].value));
      }
      dataValues[key] = Number(aggregatedValue.toString());
    }

    const result = this._computeFinalResult(dataValues, operation, metadata.operationMetadata);
    logger.info(`Processed final aggregation for ${operation}: ${JSON.stringify(result)}`);
    return { result, metadata: { ...metadata, completedAt: Date.now() } };
  }

  _computeFinalResult(dataValues, operation, operationMetadata) {
    switch (operation) {
      case OPERATION_TYPES.MEAN:
        return { mean: dataValues.sum / dataValues.count };
      case OPERATION_TYPES.VARIANCE:
        const mean = dataValues.sum / dataValues.count;
        const variance = (dataValues.sumOfSquares / dataValues.count) - (mean * mean);
        return { variance };
      case OPERATION_TYPES.STANDARD_DEVIATION:
        const varianceForStdDev = this._computeFinalResult(dataValues, OPERATION_TYPES.VARIANCE, operationMetadata).variance;
        return { std_dev: Math.sqrt(varianceForStdDev) };
      case OPERATION_TYPES.CORRELATION:
        const { sumX, sumY, sumXY, sumXSquared, sumYSquared, count } = dataValues;
        const numeratorCorr = count * sumXY - sumX * sumY;
        const denominatorCorr = Math.sqrt((count * sumXSquared - sumX * sumX) * (count * sumYSquared - sumY * sumY));
        return { correlation: denominatorCorr !== 0 ? numeratorCorr / denominatorCorr : 0 };
      case OPERATION_TYPES.COVARIANCE:
        const meanX = dataValues.sumX / dataValues.count;
        const meanY = dataValues.sumY / dataValues.count;
        const covariance = (dataValues.sumXY / dataValues.count) - (meanX * meanY);
        return { covariance };
      case OPERATION_TYPES.PERCENTILE:
      case OPERATION_TYPES.MEDIAN:
        const percentile = operationMetadata.percentile;
        const histogram = dataValues.histogram;
        const min = dataValues.min;
        const bucketSize = (dataValues.max - min) / operationMetadata.numBuckets;
        let cumulative = 0;
        const target = (percentile / 100) * dataValues.count;
        for (let i = 0; i < histogram.length; i++) {
          cumulative += histogram[i];
          if (cumulative >= target) {
            const bucketStart = min + i * bucketSize;
            return { value: bucketStart + bucketSize / 2 };
          }
        }
        return { value: min };
      case OPERATION_TYPES.MIN:
        return { min: dataValues.min };
      case OPERATION_TYPES.MAX:
        return { max: dataValues.max };
      case OPERATION_TYPES.T_TEST:
        if (operationMetadata.testType === 'paired') {
          const { sumD, sumDSquared, count } = dataValues;
          const meanD = sumD / count;
          const varianceD = (sumDSquared / count) - (meanD * meanD);
          const tStatistic = meanD / Math.sqrt(varianceD / count);
          return { tStatistic };
        } else {
          const { sum1, sumSquared1, count1, sum2, sumSquared2, count2 } = dataValues;
          const mean1 = sum1 / count1;
          const mean2 = sum2 / count2;
          const var1 = (sumSquared1 / count1) - (mean1 * mean1);
          const var2 = (sumSquared2 / count2) - (mean2 * mean2);
          const pooledVar = (var1 / count1) + (var2 / count2);
          const tStatistic = (mean1 - mean2) / Math.sqrt(pooledVar);
          return { tStatistic };
        }
      case OPERATION_TYPES.CHI_SQUARE:
        const chiSquareValue = dataValues.components.reduce((acc, val) => acc + val, 0);
        return { chiSquareValue };
      case OPERATION_TYPES.LINEAR_REGRESSION:
        const { sumX, sumY, sumXY, sumXSquared, count } = dataValues;
        const slope = (count * sumXY - sumX * sumY) / (count * sumXSquared - sumX * sumX);
        const intercept = (sumY - slope * sumX) / count;
        return { slope, intercept };
      case OPERATION_TYPES.HISTOGRAM:
        const histogramResult = dataValues.histogram.map((count, i) => ({ bucket: i, count }));
        return { histogram: histogramResult, totalCount: dataValues.histogram.reduce((acc, val) => acc + val, 0) };
      default:
        throw new Error(`Unsupported operation: ${operation}`);
    }
  }

  _aggregateFinalResults(nodeResults, operation, privacyParameters) {
    switch (operation) {
      case OPERATION_TYPES.HISTOGRAM:
        const firstResult = nodeResults[0].result;
        const aggregatedHistogram = firstResult.histogram.map(bucket => ({ ...bucket }));
        for (let i = 1; i < nodeResults.length; i++) {
          const nodeHistogram = nodeResults[i].result.histogram;
          for (let j = 0; j < aggregatedHistogram.length; j++) {
            aggregatedHistogram[j].count += nodeHistogram[j].count;
          }
        }
        const totalCount = aggregatedHistogram.reduce((sum, bucket) => sum + bucket.count, 0);
        return {
          result: { ...firstResult, histogram: aggregatedHistogram, totalCount },
          metadata: nodeResults[0].metadata
        };
      default:
        return nodeResults[0];
    }
  }

  _compareResults(result1, result2, operation) {
    const r1 = result1.result;
    const r2 = result2.result;
    switch (operation) {
      case OPERATION_TYPES.MEAN:
        return Math.abs(r1.mean - r2.mean) < 1e-9;
      case OPERATION_TYPES.VARIANCE:
        return Math.abs(r1.variance - r2.variance) < 1e-9;
      case OPERATION_TYPES.STANDARD_DEVIATION:
        return Math.abs(r1.std_dev - r2.std_dev) < 1e-9;
      case OPERATION_TYPES.CORRELATION:
        return Math.abs(r1.correlation - r2.correlation) < 1e-9;
      case OPERATION_TYPES.COVARIANCE:
        return Math.abs(r1.covariance - r2.covariance) < 1e-9;
      case OPERATION_TYPES.PERCENTILE:
      case OPERATION_TYPES.MEDIAN:
        return Math.abs(r1.value - r2.value) < 1e-9;
      case OPERATION_TYPES.MIN:
        return Math.abs(r1.min - r2.min) < 1e-9;
      case OPERATION_TYPES.MAX:
        return Math.abs(r1.max - r2.max) < 1e-9;
      case OPERATION_TYPES.T_TEST:
        return Math.abs(r1.tStatistic - r2.tStatistic) < 1e-9;
      case OPERATION_TYPES.CHI_SQUARE:
        return Math.abs(r1.chiSquareValue - r2.chiSquareValue) < 1e-9;
      case OPERATION_TYPES.LINEAR_REGRESSION:
        return Math.abs(r1.slope - r2.slope) < 1e-9 && Math.abs(r1.intercept - r2.intercept) < 1e-9;
      case OPERATION_TYPES.HISTOGRAM:
        if (r1.histogram.length !== r2.histogram.length) return false;
        for (let i = 0; i < r1.histogram.length; i++) {
          if (Math.abs(r1.histogram[i].count - r2.histogram[i].count) > 1e-9) return false;
        }
        return true;
      default:
        return JSON.stringify(r1) === JSON.stringify(r2);
    }
  }

  _generateLaplaceNoise(epsilon, sensitivity) {
    const scale = sensitivity / epsilon;
    const uniform = Math.random() - 0.5;
    const sign = uniform >= 0 ? 1 : -1;
    return sign * scale * Math.log(1 - 2 * Math.abs(uniform));
  }

  _generateVerificationMaterial(data, metadata) {
    const commitments = {};
    for (const key of Object.keys(data)) {
      if (key === 'histogram') {
        commitments[key] = data[key].map(bucketCount => this._createCommitment(bucketCount.toString()));
      } else if (typeof data[key] === 'number') {
        commitments[key] = this._createCommitment(data[key].toString());
      }
    }
    const operationCommitment = poseidonHashSync([metadata.operation, metadata.timestamp.toString()]);
    return {
      dataCommitments: commitments,
      operationCommitment,
      metadata: { commitmentType: 'poseidon', timestamp: Date.now() }
    };
  }

  _createCommitment(value) {
    const blindingFactor = randomFieldElement();
    const commitment = poseidonHashSync([value, blindingFactor]);
    return { commitment, blindingFactor };
  }

  _verifyWithMaterial(result, verificationMaterial) {
    return true; // Placeholder
  }
}

/**
 * SMPC Node for privacy-preserving distributed computation
 * @class SMPCNode
 * @extends EventEmitter
 */
class SMPCNode extends EventEmitter {
  constructor({
    nodeId,
    coordinatorUrl,
    capabilities = {},
    supportedProtocols = ['average', 'statistical'],
    protocols = {},
    authentication = {},
    encryption = {},
    maxConcurrentComputations = 5,
    enablePeerToPeer = true,
    enableLocalEncryption = true
  }) {
    super();
    this.nodeId = nodeId || uuidv4();
    this.coordinatorUrl = coordinatorUrl;
    this.capabilities = {
      computePower: 1.0,
      maxStorage: 10 * 1024 * 1024,
      supportsBatchComputation: true,
      ...capabilities
    };
    this.supportedProtocols = supportedProtocols;
    this.authentication = authentication;
    this.encryption = encryption;
    this.maxConcurrentComputations = maxConcurrentComputations;
    this.enablePeerToPeer = enablePeerToPeer;
    this.enableLocalEncryption = enableLocalEncryption;

    this.state = NodeState.IDLE;
    this.peers = new Map();
    this.activeComputations = new Map();
    this.computationQueue = [];
    this.pendingMessages = new Map();

    this.protocols = {
      average: protocols.average || new AverageProtocol(),
      statistical: protocols.statistical || new StatisticalProtocol(),
      ...protocols
    };

    this.computationShares = new Map();
    this.computationResults = new Map();

    logger.info(`SMPC Node ${this.nodeId} initialized with capabilities:`, this.capabilities);
  }

  async connect() {
    try {
      logger.info(`Connecting to coordinator at ${this.coordinatorUrl}`);
      this.socket = new WebSocket(this.coordinatorUrl);
      this.socket.on('open', this._handleSocketOpen.bind(this));
      this.socket.on('message', this._handleSocketMessage.bind(this));
      this.socket.on('error', this._handleSocketError.bind(this));
      this.socket.on('close', this._handleSocketClose.bind(this));
      return new Promise((resolve, reject) => {
        const onOpen = () => { this.socket.removeListener('error', onError); resolve(true); };
        const onError = (error) => { this.socket.removeListener('open', onOpen); reject(error); };
        this.socket.once('open', onOpen);
        this.socket.once('error', onError);
        setTimeout(() => {
          this.socket.removeListener('open', onOpen);
          this.socket.removeListener('error', onError);
          reject(new Error('Connection timeout'));
        }, 10000);
      });
    } catch (error) {
      logger.error('Failed to connect to coordinator:', error);
      this.state = NodeState.ERROR;
      throw error;
    }
  }

  async disconnect() {
    try {
      logger.info('Disconnecting from coordinator');
      if (this.socket) {
        this.socket.close();
        this.socket = null;
      }
      for (const [peerId, peerConnection] of this.peers.entries()) {
        logger.debug(`Closing connection to peer ${peerId}`);
        peerConnection.close();
      }
      this.peers.clear();
      this.state = NodeState.IDLE;
      this.emit('disconnected');
      logger.info('Disconnected from coordinator');
      return true;
    } catch (error) {
      logger.error('Error during disconnection:', error);
      return false;
    }
  }

  async handleMessage(message) {
    try {
      logger.debug(`Received message: ${JSON.stringify(message)}`);
      if (!message || !message.type) throw new Error('Invalid message format');

      switch (message.type) {
        case 'command':
          return this.processCommand(message.command, message.params, message.metadata);
        case 'share':
          return this.processShare(message.computationId, message.share, message.metadata);
        case 'result':
          return this.processResult(message.computationId, message.result, message.metadata);
        case 'ping':
          return { type: 'pong', timestamp: Date.now() };
        case 'error':
          logger.warn(`Received error message: ${message.error}`);
          return { type: 'error_ack', error: message.error, timestamp: Date.now() };
        default:
          logger.warn(`Received unknown message type: ${message.type}`);
          return { type: 'error', error: 'Unknown message type', timestamp: Date.now() };
      }
    } catch (error) {
      logger.error('Error handling message:', error);
      return { type: 'error', error: error.message, timestamp: Date.now() };
    }
  }

  async sendMessage(message, destination = 'coordinator') {
    try {
      if (!message.messageId) message.messageId = uuidv4();
      if (!message.timestamp) message.timestamp = Date.now();
      message.sender = this.nodeId;
      logger.debug(`Sending message to ${destination}: ${JSON.stringify(message)}`);

      if (destination === 'coordinator') {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) throw new Error('Not connected to coordinator');
        return new Promise((resolve, reject) => {
          this.pendingMessages.set(message.messageId, { resolve, reject, timestamp: Date.now(), message });
          this.socket.send(JSON.stringify(message), (error) => {
            if (error) {
              this.pendingMessages.delete(message.messageId);
              reject(error);
            }
          });
          setTimeout(() => {
            if (this.pendingMessages.has(message.messageId)) {
              this.pendingMessages.delete(message.messageId);
              reject(new Error('Message timeout'));
            }
          }, 30000);
        });
      } else if (this.peers.has(destination)) {
        const peerConnection = this.peers.get(destination);
        return new Promise((resolve, reject) => {
          this.pendingMessages.set(message.messageId, { resolve, reject, timestamp: Date.now(), message });
          peerConnection.send(JSON.stringify(message), (error) => {
            if (error) {
              this.pendingMessages.delete(message.messageId);
              reject(error);
            }
          });
          setTimeout(() => {
            if (this.pendingMessages.has(message.messageId)) {
              this.pendingMessages.delete(message.messageId);
              reject(new Error('Message timeout'));
            }
          }, 30000);
        });
      } else {
        throw new Error(`Unknown destination: ${destination}`);
      }
    } catch (error) {
      logger.error(`Failed to send message to ${destination}:`, error);
      throw error;
    }
  }

  async processCommand(command, params, metadata) {
    try {
      logger.info(`Processing command: ${command}`);
      if (!command) throw new Error('Invalid command');

      switch (command) {
        case 'initialize':
          return this.initializeComputation(params, metadata);
        case 'share':
          return this.shareData(params.computationId, params.sessionKey, metadata);
        case 'compute':
          return this.compute(params.computationId, metadata);
        case 'aggregate':
          return this.aggregate(params.computationId, params.results, metadata);
        case 'verify':
          return this.verify(params.computationId, params.result, metadata);
        case 'abort':
          return this.abortComputation(params.computationId, params.reason, metadata);
        case 'status':
          return this.getStatus(params.computationId);
        case 'capabilities':
          return {
            type: 'capabilities',
            nodeId: this.nodeId,
            capabilities: this.capabilities,
            supportedProtocols: this.supportedProtocols,
            activeComputations: this.activeComputations.size,
            state: this.state,
            timestamp: Date.now()
          };
        case 'connect_peer':
          return this.connectToPeer(params.peerId, params.peerUrl, metadata);
        case 'disconnect_peer':
          return this.disconnectFromPeer(params.peerId, metadata);
        default:
          logger.warn(`Unknown command: ${command}`);
          return { type: 'error', error: `Unknown command: ${command}`, timestamp: Date.now() };
      }
    } catch (error) {
      logger.error(`Error processing command ${command}:`, error);
      return { type: 'error', command, error: error.message, timestamp: Date.now() };
    }
  }

  async initializeComputation(params, metadata) {
    try {
      logger.info(`Initializing computation: ${params.computationId}`);
      if (!params.computationId || !params.type || !params.sessionKey) throw new Error('Invalid initialization parameters');
      if (this.activeComputations.has(params.computationId)) {
        return {
          type: 'initialization_result',
          success: true,
          computationId: params.computationId,
          message: 'Computation already initialized',
          timestamp: Date.now()
        };
      }
      if (!this.supportedProtocols.includes(params.type)) throw new Error(`Unsupported protocol: ${params.type}`);
      if (this.activeComputations.size >= this.maxConcurrentComputations) {
        this.computationQueue.push({ params, metadata, timestamp: Date.now() });
        logger.info(`Computation ${params.computationId} queued (${this.computationQueue.length} in queue)`);
        return {
          type: 'initialization_result',
          success: true,
          computationId: params.computationId,
          queued: true,
          queuePosition: this.computationQueue.length,
          message: 'Computation queued',
          timestamp: Date.now()
        };
      }

      const computationState = {
        id: params.computationId,
        type: params.type,
        sessionKey: params.sessionKey,
        threshold: params.threshold || 1,
        dataVaultIds: params.dataVaultIds || [],
        privacyParameters: params.privacyParameters || {},
        state: NodeState.INITIALIZING,
        peers: params.peers || [],
        receivedShares: new Map(),
        receivedResults: new Map(),
        share: null,
        result: null,
        startedAt: Date.now(),
        updatedAt: Date.now()
      };
      this.activeComputations.set(params.computationId, computationState);

      if (this.enablePeerToPeer) await this._initializePeerConnections(computationState);

      computationState.state = NodeState.WAITING_FOR_PEERS;
      computationState.updatedAt = Date.now();

      this.emit('computation:initialized', { computationId: params.computationId, type: params.type });
      logger.info(`Computation ${params.computationId} initialized successfully`);
      return {
        type: 'initialization_result',
        success: true,
        computationId: params.computationId,
        message: 'Computation initialized successfully',
        timestamp: Date.now()
      };
    } catch (error) {
      logger.error(`Failed to initialize computation:`, error);
      return { type: 'error', error: `Initialization failed: ${error.message}`, timestamp: Date.now() };
    }
  }

  async shareData(computationId, sessionKey, metadata) {
    try {
      logger.info(`Sharing data for computation: ${computationId}`);
      if (!computationId || !sessionKey) throw new Error('Invalid share parameters');
      if (!this.activeComputations.has(computationId)) throw new Error(`Computation ${computationId} not found`);

      const computation = this.activeComputations.get(computationId);
      if (computation.sessionKey !== sessionKey) throw new Error('Invalid session key');

      computation.state = NodeState.SHARING;
      computation.updatedAt = Date.now();

      const share = this.computationShares.get(computationId);
      if (!share) {
        logger.warn(`No share found for computation ${computationId}`);
        return { type: 'share_result', success: false, computationId, error: 'No share found', timestamp: Date.now() };
      }

      computation.share = share;

      if (this.enablePeerToPeer && computation.peers.length > 0) {
        await this._shareToPeers(computation, share);
      } else {
        await this.sendMessage({ type: 'share_notification', computationId, shareId: uuidv4(), timestamp: Date.now() });
      }

      this.emit('share:sent', { computationId, timestamp: Date.now() });
      computation.state = NodeState.WAITING_FOR_PEERS;
      computation.updatedAt = Date.now();
      logger.info(`Data shared for computation ${computationId}`);
      return { type: 'share_result', success: true, computationId, message: 'Data shared successfully', timestamp: Date.now() };
    } catch (error) {
      logger.error(`Failed to share data for computation ${computationId}:`, error);
      if (this.activeComputations.has(computationId)) {
        const computation = this.activeComputations.get(computationId);
        computation.state = NodeState.ERROR;
        computation.error = error.message;
        computation.updatedAt = Date.now();
      }
      return { type: 'error', error: `Share failed: ${error.message}`, computationId, timestamp: Date.now() };
    }
  }

  async processShare(computationId, share, metadata) {
    try {
      logger.info(`Processing share for computation: ${computationId}`);
      if (!computationId || !share) throw new Error('Invalid share parameters');
      if (!this.activeComputations.has(computationId)) throw new Error(`Computation ${computationId} not found`);

      const computation = this.activeComputations.get(computationId);
      if (!computation.peers.includes(metadata.sender)) throw new Error(`Share received from unknown peer: ${metadata.sender}`);

      computation.receivedShares.set(metadata.sender, { share, timestamp: Date.now() });
      logger.debug(`Received share from ${metadata.sender} for computation ${computationId}`);
      this.emit('share:received', { computationId, sender: metadata.sender, timestamp: Date.now() });

      if (computation.receivedShares.size >= computation.threshold - 1) {
        logger.info(`All required shares received for computation ${computationId}`);
        computation.state = NodeState.COMPUTING;
        computation.updatedAt = Date.now();
        await this.sendMessage({
          type: 'shares_complete',
          computationId,
          peersReceived: Array.from(computation.receivedShares.keys()),
          timestamp: Date.now()
        });
        if (metadata.autoCompute) this.compute(computationId, { autoCompute: true });
      }

      return { type: 'share_ack', success: true, computationId, message: 'Share processed successfully', timestamp: Date.now() };
    } catch (error) {
      logger.error(`Failed to process share for computation ${computationId}:`, error);
      return { type: 'error', error: `Share processing failed: ${error.message}`, computationId, timestamp: Date.now() };
    }
  }

  async compute(computationId, metadata = {}) {
    try {
      logger.info(`Starting computation: ${computationId}`);
      if (!computationId) throw new Error('Invalid computation parameters');
      if (!this.activeComputations.has(computationId)) throw new Error(`Computation ${computationId} not found`);

      const computation = this.activeComputations.get(computationId);
      if (computation.state !== NodeState.COMPUTING && computation.state !== NodeState.WAITING_FOR_PEERS) throw new Error(`Invalid state for computation: ${computation.state}`);

      computation.state = NodeState.COMPUTING;
      computation.updatedAt = Date.now();

      const ownShare = computation.share;
      const peerShares = Array.from(computation.receivedShares.values()).map(item => item.share);
      const protocol = this.protocols[computation.type];
      if (!protocol) throw new Error(`Protocol not available: ${computation.type}`);

      const result = await protocol.processShareAtNode({
        share: ownShare,
        peerShares,
        metadata: { ...metadata, computationId, type: computation.type, privacyParameters: computation.privacyParameters }
      });

      computation.result = result;
      this.computationResults.set(computationId, result);
      computation.state = NodeState.AGGREGATING;
      computation.updatedAt = Date.now();

      if (this.enablePeerToPeer && computation.peers.length > 0) await this._shareResultToPeers(computation, result);
      await this.sendMessage({ type: 'result', computationId, result, timestamp: Date.now() });

      this.emit('computation:completed', { computationId, timestamp: Date.now() });
      logger.info(`Computation ${computationId} completed successfully`);
      return { type: 'computation_result', success: true, computationId, message: 'Computation completed successfully', timestamp: Date.now() };
    } catch (error) {
      logger.error(`Failed to compute for computation ${computationId}:`, error);
      if (this.activeComputations.has(computationId)) {
        const computation = this.activeComputations.get(computationId);
        computation.state = NodeState.ERROR;
        computation.error = error.message;
        computation.updatedAt = Date.now();
      }
      return { type: 'error', error: `Computation failed: ${error.message}`, computationId, timestamp: Date.now() };
    }
  }

  async processResult(computationId, result, metadata) {
    try {
      logger.info(`Processing result for computation: ${computationId}`);
      if (!computationId || !result) throw new Error('Invalid result parameters');
      if (!this.activeComputations.has(computationId)) throw new Error(`Computation ${computationId} not found`);

      const computation = this.activeComputations.get(computationId);
      if (!computation.peers.includes(metadata.sender)) throw new Error(`Result received from unknown peer: ${metadata.sender}`);

      computation.receivedResults.set(metadata.sender, { result, timestamp: Date.now() });
      logger.debug(`Received result from ${metadata.sender} for computation ${computationId}`);
      this.emit('result:received', { computationId, sender: metadata.sender, timestamp: Date.now() });

      if (computation.receivedResults.size >= computation.threshold - 1) {
        logger.info(`All required results received for computation ${computationId}`);
        computation.state = NodeState.VERIFYING;
        computation.updatedAt = Date.now();
        await this.sendMessage({
          type: 'results_complete',
          computationId,
          peersReceived: Array.from(computation.receivedResults.keys()),
          timestamp: Date.now()
        });
        if (metadata.autoVerify) {
          const allResults = [computation.result, ...Array.from(computation.receivedResults.values()).map(item => item.result)];
          this.verify(computationId, allResults, { autoVerify: true });
        }
      }

      return { type: 'result_ack', success: true, computationId, message: 'Result processed successfully', timestamp: Date.now() };
    } catch (error) {
      logger.error(`Failed to process result for computation ${computationId}:`, error);
      return { type: 'error', error: `Result processing failed: ${error.message}`, computationId, timestamp: Date.now() };
    }
  }

  async verify(computationId, results, metadata = {}) {
    try {
      logger.info(`Verifying results for computation: ${computationId}`);
      if (!computationId || !results) throw new Error('Invalid verification parameters');
      if (!this.activeComputations.has(computationId)) throw new Error(`Computation ${computationId} not found`);

      const computation = this.activeComputations.get(computationId);
      computation.state = NodeState.VERIFYING;
      computation.updatedAt = Date.now();

      const protocol = this.protocols[computation.type];
      if (!protocol) throw new Error(`Protocol not available: ${computation.type}`);

      const resultsArray = Array.isArray(results) ? results : [results];
      const isValid = await protocol.verifyResult(computation.result, { nodeResults: resultsArray, privacyParameters: computation.privacyParameters });

      computation.verified = isValid;
      computation.verifiedAt = Date.now();

      await this.sendMessage({ type: 'verification_result', computationId, verified: isValid, timestamp: Date.now() });
      this.emit('result:verified', { computationId, verified: isValid, timestamp: Date.now() });

      if (metadata.autoCleanup) this._cleanupComputation(computationId);
      logger.info(`Verification for computation ${computationId} completed: ${isValid}`);
      return {
        type: 'verification_result',
        success: true,
        computationId,
        verified: isValid,
        message: isValid ? 'Verification successful' : 'Verification failed',
        timestamp: Date.now()
      };
    } catch (error) {
      logger.error(`Failed to verify results for computation ${computationId}:`, error);
      if (this.activeComputations.has(computationId)) {
        const computation = this.activeComputations.get(computationId);
        computation.state = NodeState.ERROR;
        computation.error = error.message;
        computation.updatedAt = Date.now();
      }
      return { type: 'error', error: `Verification failed: ${error.message}`, computationId, timestamp: Date.now() };
    }
  }

  async abortComputation(computationId, reason, metadata = {}) {
    try {
      logger.info(`Aborting computation: ${computationId}`);
      if (!computationId) throw new Error('Invalid abort parameters');
      if (!this.activeComputations.has(computationId)) {
        return { type: 'abort_result', success: true, computationId, message: 'Computation not found, already aborted', timestamp: Date.now() };
      }

      const computation = this.activeComputations.get(computationId);
      const previousState = computation.state;
      computation.state = NodeState.ERROR;
      computation.error = reason || 'Aborted by command';
      computation.abortedAt = Date.now();
      computation.updatedAt = Date.now();

      if (this.enablePeerToPeer && computation.peers.length > 0) {
        for (const peerId of computation.peers) {
          if (this.peers.has(peerId)) {
            await this.sendMessage({ type: 'abort_notification', computationId, reason: computation.error, timestamp: Date.now() }, peerId);
          }
        }
      }

      this.emit('computation:aborted', { computationId, reason: computation.error, previousState, timestamp: Date.now() });
      this._cleanupComputation(computationId);
      logger.info(`Computation ${computationId} aborted successfully`);
      return { type: 'abort_result', success: true, computationId, message: 'Computation aborted successfully', timestamp: Date.now() };
    } catch (error) {
      logger.error(`Failed to abort computation ${computationId}:`, error);
      return { type: 'error', error: `Abort failed: ${error.message}`, computationId, timestamp: Date.now() };
    }
  }

  _cleanupComputation(computationId) {
    logger.info(`Cleaning up computation ${computationId}`);
    this.activeComputations.delete(computationId);
    if (this.computationQueue.length > 0) {
      const nextComputation = this.computationQueue.shift();
      this.initializeComputation(nextComputation.params, nextComputation.metadata).catch(error => {
        logger.error(`Failed to initialize queued computation:`, error);
      });
    }
  }

  _handleSocketOpen() {
    logger.info('Connected to coordinator');
    this.state = NodeState.IDLE;
    this.sendMessage({
      type: 'registration',
      nodeId: this.nodeId,
      capabilities: this.capabilities,
      supportedProtocols: this.supportedProtocols,
      timestamp: Date.now()
    }).catch(error => {
      logger.error('Failed to register with coordinator:', error);
    });
    this.emit('connected');
  }

  _handleSocketMessage(data) {
    try {
      const message = JSON.parse(data);
      if (message.inReplyTo && this.pendingMessages.has(message.inReplyTo)) {
        const pendingMessage = this.pendingMessages.get(message.inReplyTo);
        this.pendingMessages.delete(message.inReplyTo);
        if (message.type === 'error') {
          pendingMessage.reject(new Error(message.error));
        } else {
          pendingMessage.resolve(message);
        }
        return;
      }
      this.handleMessage(message).then(response => {
        if (message.messageId) {
          response.inReplyTo = message.messageId;
          this.socket.send(JSON.stringify(response));
        }
      }).catch(error => {
        logger.error('Error handling socket message:', error);
        if (message.messageId) {
          const errorResponse = { type: 'error', error: error.message, inReplyTo: message.messageId, timestamp: Date.now() };
          this.socket.send(JSON.stringify(errorResponse));
        }
      });
    } catch (error) {
      logger.error('Failed to parse message from coordinator:', error);
    }
  }

  _handleSocketError(error) {
    logger.error('WebSocket error:', error);
    this.state = NodeState.ERROR;
    this.emit('error', error);
  }

  _handleSocketClose() {
    logger.info('Disconnected from coordinator');
    for (const [messageId, pendingMessage] of this.pendingMessages.entries()) {
      pendingMessage.reject(new Error('Connection closed'));
      this.pendingMessages.delete(messageId);
    }
    this.state = NodeState.IDLE;
    this.emit('disconnected');
    if (this.reconnectOnDisconnect) {
      setTimeout(() => {
        logger.info('Attempting to reconnect to coordinator...');
        this.connect().catch(error => {
          logger.error('Failed to reconnect to coordinator:', error);
        });
      }, 5000);
    }
  }

  _handlePeerMessage(peerId, message) {
    try {
      logger.debug(`Received message from peer ${peerId}: ${JSON.stringify(message)}`);
      if (!message.metadata) message.metadata = {};
      message.metadata.sender = peerId;
      this.handleMessage(message).then(response => {
        if (message.messageId && this.peers.has(peerId)) {
          response.inReplyTo = message.messageId;
          this.peers.get(peerId).send(JSON.stringify(response));
        }
      }).catch(error => {
        logger.error(`Error handling message from peer ${peerId}:`, error);
        if (message.messageId && this.peers.has(peerId)) {
          const errorResponse = { type: 'error', error: error.message, inReplyTo: message.messageId, timestamp: Date.now() };
          this.peers.get(peerId).send(JSON.stringify(errorResponse));
        }
      });
    } catch (error) {
      logger.error(`Failed to handle message from peer ${peerId}:`, error);
    }
  }

  _handlePeerDisconnect(peerId, error) {
    logger.info(`Peer ${peerId} disconnected${error ? `: ${error.message}` : ''}`);
    this.peers.delete(peerId);
    for (const [computationId, computation] of this.activeComputations.entries()) {
      if (computation.peers.includes(peerId)) {
        const peerIndex = computation.peers.indexOf(peerId);
        if (peerIndex !== -1) computation.peers.splice(peerIndex, 1);
        computation.receivedShares.delete(peerId);
        computation.receivedResults.delete(peerId);
        if (computation.peers.length + 1 < computation.threshold) {
          this.abortComputation(computationId, `Peer ${peerId} disconnected, not enough peers to meet threshold`);
        }
      }
    }
    this.emit('peer:disconnected', { peerId, error: error ? error.message : undefined, timestamp: Date.now() });
  }

  async _initializePeerConnections(computation) {
    if (!this.enablePeerToPeer || computation.peers.length === 0) return;
    logger.info(`Initializing peer connections for computation ${computation.id}`);
    for (const peerId of computation.peers) {
      if (!this.peers.has(peerId)) {
        try {
          const response = await this.sendMessage({ type: 'get_peer_url', peerId, computationId: computation.id, timestamp: Date.now() });
          if (response.peerUrl) await this.connectToPeer(peerId, response.peerUrl);
          else logger.warn(`No URL provided for peer ${peerId}`);
        } catch (error) {
          logger.error(`Failed to connect to peer ${peerId}:`, error);
        }
      }
    }
  }

  async _shareToPeers(computation, share) {
    if (!this.enablePeerToPeer || computation.peers.length === 0) return;
    logger.info(`Sharing data with peers for computation ${computation.id}`);
    for (const peerId of computation.peers) {
      if (this.peers.has(peerId)) {
        try {
          await this.sendMessage({ type: 'share', computationId: computation.id, share, timestamp: Date.now(), metadata: { sender: this.nodeId } }, peerId);
          logger.debug(`Shared data with peer ${peerId} for computation ${computation.id}`);
        } catch (error) {
          logger.error(`Failed to share data with peer ${peerId}:`, error);
        }
      } else {
        logger.warn(`Cannot share data with peer ${peerId}: not connected`);
      }
    }
  }

  async _shareResultToPeers(computation, result) {
    if (!this.enablePeerToPeer || computation.peers.length === 0) return;
    logger.info(`Sharing result with peers for computation ${computation.id}`);
    for (const peerId of computation.peers) {
      if (this.peers.has(peerId)) {
        try {
          await this.sendMessage({ type: 'result', computationId: computation.id, result, timestamp: Date.now(), metadata: { sender: this.nodeId } }, peerId);
          logger.debug(`Shared result with peer ${peerId} for computation ${computation.id}`);
        } catch (error) {
          logger.error(`Failed to share result with peer ${peerId}:`, error);
        }
      } else {
        logger.warn(`Cannot share result with peer ${peerId}: not connected`);
      }
    }
  }

  getStatus(computationId) {
    if (!computationId) {
      return {
        type: 'status',
        nodeId: this.nodeId,
        state: this.state,
        activeComputations: this.activeComputations.size,
        queuedComputations: this.computationQueue.length,
        supportedProtocols: this.supportedProtocols,
        timestamp: Date.now()
      };
    }
    if (!this.activeComputations.has(computationId)) {
      return { type: 'error', error: `Computation ${computationId} not found`, timestamp: Date.now() };
    }
    const computation = this.activeComputations.get(computationId);
    return {
      type: 'computation_status',
      computationId,
      state: computation.state,
      startedAt: computation.startedAt,
      updatedAt: computation.updatedAt,
      peers: computation.peers,
      receivedShares: computation.receivedShares.size,
      receivedResults: computation.receivedResults.size,
      verified: computation.verified,
      error: computation.error,
      timestamp: Date.now()
    };
  }

  async connectToPeer(peerId, peerUrl, metadata = {}) {
    try {
      logger.info(`Connecting to peer ${peerId} at ${peerUrl}`);
      if (!peerId || !peerUrl) throw new Error('Invalid peer connection parameters');
      if (this.peers.has(peerId)) {
        return { type: 'peer_connection_result', success: true, peerId, message: 'Already connected to peer', timestamp: Date.now() };
      }
      const peerSocket = new WebSocket(peerUrl);
      await new Promise((resolve, reject) => {
        const onOpen = () => { peerSocket.removeListener('error', onError); resolve(); };
        const onError = (error) => { peerSocket.removeListener('open', onOpen); reject(error); };
        peerSocket.once('open', onOpen);
        peerSocket.once('error', onError);
        setTimeout(() => {
          peerSocket.removeListener('open', onOpen);
          peerSocket.removeListener('error', onError);
          reject(new Error('Peer connection timeout'));
        }, 10000);
      });
      peerSocket.on('message', (data) => {
        try {
          const message = JSON.parse(data);
          this._handlePeerMessage(peerId, message);
        } catch (error) {
          logger.error(`Error handling message from peer ${peerId}:`, error);
        }
      });
      peerSocket.on('error', (error) => this._handlePeerDisconnect(peerId, error));
      peerSocket.on('close', () => this._handlePeerDisconnect(peerId));
      this.peers.set(peerId, peerSocket);
      this.emit('peer:connected', { peerId, timestamp: Date.now() });
      logger.info(`Connected to peer ${peerId} successfully`);
      return { type: 'peer_connection_result', success: true, peerId, message: 'Connected to peer successfully', timestamp: Date.now() };
    } catch (error) {
      logger.error(`Failed to connect to peer ${peerId}:`, error);
      return { type: 'error', error: `Peer connection failed: ${error.message}`, timestamp: Date.now() };
    }
  }

  async disconnectFromPeer(peerId, metadata = {}) {
    try {
      logger.info(`Disconnecting from peer ${peerId}`);
      if (!peerId) throw new Error('Invalid peer disconnection parameters');
      if (!this.peers.has(peerId)) {
        return { type: 'peer_disconnection_result', success: true, peerId, message: 'Not connected to peer', timestamp: Date.now() };
      }
      const peerSocket = this.peers.get(peerId);
      peerSocket.close();
      this.peers.delete(peerId);
      this.emit('peer:disconnected', { peerId, timestamp: Date.now() });
      logger.info(`Disconnected from peer ${peerId} successfully`);
      return { type: 'peer_disconnection_result', success: true, peerId, message: 'Disconnected from peer successfully', timestamp: Date.now() };
    } catch (error) {
      logger.error(`Failed to disconnect from peer ${peerId}:`, error);
      return { type: 'error', error: `Peer disconnection failed: ${error.message}`, timestamp: Date.now() };
    }
  }

  assignShare(computationId, share) {
    try {
      logger.info(`Assigning share to computation: ${computationId}`);
      if (!computationId || !share) throw new Error('Invalid share assignment parameters');
      this.computationShares.set(computationId, share);
      logger.debug(`Share assigned to computation ${computationId}`);
      return true;
    } catch (error) {
      logger.error(`Failed to assign share to computation ${computationId}:`, error);
      return false;
    }
  }

  getLoad() {
    const load = this.activeComputations.size / this.maxConcurrentComputations;
    return Math.min(1, Math.max(0, load));
  }

  async aggregate(computationId, results, metadata = {}) {
    try {
      logger.info(`Aggregating results for computation: ${computationId}`);
      if (!computationId || !results) throw new Error('Invalid aggregation parameters');
      if (!this.activeComputations.has(computationId)) throw new Error(`Computation ${computationId} not found`);

      const computation = this.activeComputations.get(computationId);
      computation.state = NodeState.AGGREGATING;
      computation.updatedAt = Date.now();

      const protocol = this.protocols[computation.type];
      if (!protocol) throw new Error(`Protocol not available: ${computation.type}`);

      const aggregatedResult = await protocol.aggregateResults(results, computation.privacyParameters);
      computation.aggregatedResult = aggregatedResult;

      await this.sendMessage({ type: 'aggregation_result', computationId, result: aggregatedResult, timestamp: Date.now() });
      this.emit('results:aggregated', { computationId, timestamp: Date.now() });
      logger.info(`Aggregation for computation ${computationId} completed successfully`);
      return { type: 'aggregation_result', success: true, computationId, message: 'Aggregation completed successfully', timestamp: Date.now() };
    } catch (error) {
      logger.error(`Failed to aggregate results for computation ${computationId}:`, error);
      if (this.activeComputations.has(computationId)) {
        const computation = this.activeComputations.get(computationId);
        computation.state = NodeState.ERROR;
        computation.error = error.message;
        computation.updatedAt = Date.now();
      }
      return { type: 'error', error: `Aggregation failed: ${error.message}`, computationId, timestamp: Date.now() };
    }
  }

  _cleanupComputation(computationId) {
    logger.info(`Cleaning up computation ${computationId}`);
    this.activeComputations.delete(computationId);
    if (this.computationQueue.length > 0) {
      const nextComputation = this.computationQueue.shift();
      this.initializeComputation(nextComputation.params, nextComputation.metadata).catch(error => {
        logger.error(`Failed to initialize queued computation:`, error);
      });
    }
  }
}

/**
 * Create an SMPC Node with default configuration
 * @param {Object} [options={}] - Configuration options for the node
 * @returns {SMPCNode} Configured SMPC Node instance
 */
function createSMPCNode(options = {}) {
  const node = new SMPCNode(options);
  if (options.autoConnect) {
    node.connect().catch(error => {
      logger.error('Failed to auto-connect to coordinator:', error);
    });
  }
  return node;
}

module.exports = {
  SMPCNode,
  createSMPCNode,
  NodeState
};
