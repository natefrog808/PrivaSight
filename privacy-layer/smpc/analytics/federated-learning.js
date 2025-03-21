/**
 * @fileoverview Federated Learning implementation for PrivaSight
 * 
 * This module provides a comprehensive implementation of privacy-preserving federated learning,
 * enabling multiple parties to train machine learning models collaboratively without sharing raw data.
 * It supports model averaging, secure aggregation, and differential privacy techniques.
 */

const crypto = require('crypto');
const { SecretSharing } = require('../../smpc/secret-sharing');

// **Aggregation Strategies**
const AggregationStrategy = {
  FEDAVG: 'FEDAVG',           // Standard Federated Averaging
  WEIGHTED_AVERAGE: 'WEIGHTED_AVERAGE', // Weighted by dataset size or custom weights
  MEDIAN: 'MEDIAN',           // Robust to outliers
  TRIMMED_MEAN: 'TRIMMED_MEAN', // Trims extreme values
  KRUM: 'KRUM',               // Byzantine-robust aggregation
  COORDMEDIAN: 'COORDMEDIAN', // Coordinate-wise median
};

// **Model Types**
const ModelType = {
  REGRESSION: 'REGRESSION',
  CLASSIFICATION: 'CLASSIFICATION',
  CLUSTERING: 'CLUSTERING',
  NEURAL_NETWORK: 'NEURAL_NETWORK',
  CUSTOM: 'CUSTOM',
};

// **Privacy Mechanisms**
const PrivacyMechanism = {
  NONE: 'NONE',
  DIFFERENTIAL_PRIVACY: 'DIFFERENTIAL_PRIVACY',
  SECURE_AGGREGATION: 'SECURE_AGGREGATION',
  HOMOMORPHIC_ENCRYPTION: 'HOMOMORPHIC_ENCRYPTION',
  HYBRID: 'HYBRID',
};

/**
 * ### FederatedLearning Class
 * Main class for coordinating and executing federated learning.
 */
class FederatedLearning {
  /**
   * @param {Object} options - Configuration options
   * @param {ModelType} [options.modelType=ModelType.CUSTOM] - Type of model being trained
   * @param {number} [options.numRounds=100] - Maximum number of federated rounds
   * @param {number} [options.minParticipants=2] - Minimum number of participants required
   * @param {AggregationStrategy} [options.aggregationStrategy=AggregationStrategy.FEDAVG] - Aggregation method
   * @param {PrivacyMechanism} [options.privacyMechanism=PrivacyMechanism.DIFFERENTIAL_PRIVACY] - Privacy technique
   * @param {number} [options.epsilon=1.0] - Differential privacy parameter (lower = more private)
   * @param {number} [options.delta=1e-5] - Differential privacy failure probability
   * @param {number} [options.clippingThreshold=1.0] - Gradient clipping threshold
   * @param {boolean} [options.adaptiveClipping=false] - Enable adaptive clipping
   * @param {Function} [options.convergenceTest=null] - Custom convergence test function
   * @param {Object|Function} [options.modelInitializer=null] - Initial model parameters or generator
   * @param {number} [options.clientSelectionRatio=1.0] - Fraction of clients to select per round
   * @param {boolean} [options.secureAggregation=false] - Enable SMPC for aggregation
   */
  constructor(options = {}) {
    // Core settings
    this.modelType = options.modelType || ModelType.CUSTOM;
    this.numRounds = options.numRounds || 100;
    this.minParticipants = options.minParticipants || 2;
    this.currentRound = 0;
    this.clients = new Map();

    // Aggregation and training parameters
    this.aggregationStrategy = options.aggregationStrategy || AggregationStrategy.FEDAVG;
    this.clientSelectionRatio = options.clientSelectionRatio || 1.0;
    this.convergenceTest = options.convergenceTest || null;

    // Model state
    this.globalModel = options.modelInitializer || null;
    this.previousGlobalModel = null;
    this.modelMetrics = [];

    // Privacy settings
    this.privacyMechanism = options.privacyMechanism || PrivacyMechanism.DIFFERENTIAL_PRIVACY;
    this.epsilon = options.epsilon || 1.0;
    this.delta = options.delta || 1e-5;
    this.clippingThreshold = options.clippingThreshold || 1.0;
    this.adaptiveClipping = options.adaptiveClipping || false;
    this.secureAggregation = options.secureAggregation || false;
    if (this.secureAggregation) {
      this.secretSharing = new SecretSharing();
    }

    // Monitoring and state
    this.roundResults = [];
    this.convergenceCurve = [];
    this.clientPerformance = new Map();
    this.isTraining = false;
    this.eventListeners = {
      'roundComplete': [],
      'modelUpdated': [],
      'trainingComplete': [],
      'clientDropped': [],
      'error': [],
    };
    this.privacyBudgetUsed = 0;
    this.noiseScale = this._calculateInitialNoiseScale();
  }

  /** Register a new client */
  registerClient(clientId, clientInfo = {}) {
    if (this.clients.has(clientId)) throw new Error(`Client ${clientId} already registered`);
    this.clients.set(clientId, {
      id: clientId,
      datasetSize: clientInfo.datasetSize || 0,
      features: clientInfo.features || [],
      capabilities: clientInfo.capabilities || {},
      lastActive: Date.now(),
      status: 'registered',
      rounds: { participated: 0, selected: 0, completed: 0, failed: 0 },
      metrics: { avgTrainingTime: 0, avgUploadSize: 0, avgDownloadSize: 0 },
    });
    return true;
  }

  /** Unregister a client */
  unregisterClient(clientId) {
    if (!this.clients.has(clientId)) return false;
    this.clients.delete(clientId);
    this._emitEvent('clientDropped', { clientId });
    return true;
  }

  /** Initialize the global model */
  initializeGlobalModel(initializer) {
    this.globalModel = typeof initializer === 'function' ? initializer() : initializer;
    this.previousGlobalModel = this._deepCopy(this.globalModel);
    return this.globalModel;
  }

  /** Start the federated learning process */
  async startTraining() {
    if (this.isTraining) throw new Error('Training already in progress');
    if (!this.globalModel) throw new Error('Global model not initialized');
    if (this.clients.size < this.minParticipants) {
      throw new Error(`Need at least ${this.minParticipants} clients, got ${this.clients.size}`);
    }

    this.isTraining = true;
    this.currentRound = 0;
    this.privacyBudgetUsed = 0;

    try {
      while (this.currentRound < this.numRounds) {
        const roundResults = await this._executeFederatedRound();
        this.roundResults.push(roundResults);
        if (this._checkConvergence()) break;
        this.currentRound++;
      }

      this._emitEvent('trainingComplete', {
        rounds: this.currentRound,
        finalModel: this.globalModel,
        metrics: this.modelMetrics,
      });
      this.isTraining = false;
      return this.globalModel;
    } catch (error) {
      this.isTraining = false;
      this._emitEvent('error', { error });
      throw error;
    }
  }

  /** Stop training */
  stopTraining() {
    if (!this.isTraining) return false;
    this.isTraining = false;
    this._emitEvent('trainingComplete', {
      interrupted: true,
      rounds: this.currentRound,
      finalModel: this.globalModel,
      metrics: this.modelMetrics,
    });
    return true;
  }

  /** Add event listener */
  addEventListener(event, callback) {
    if (!this.eventListeners[event]) this.eventListeners[event] = [];
    this.eventListeners[event].push(callback);
  }

  /** Remove event listener */
  removeEventListener(event, callback) {
    if (!this.eventListeners[event]) return;
    this.eventListeners[event] = this.eventListeners[event].filter(cb => cb !== callback);
  }

  /** Simulate client update (for testing) */
  simulateClientUpdate(clientId, modelUpdate, metrics = {}) {
    if (!this.clients.has(clientId)) throw new Error(`Unknown client ${clientId}`);
    const processedUpdate = this._applyClientPrivacy(modelUpdate);
    const client = this.clients.get(clientId);
    client.lastActive = Date.now();
    client.rounds.completed++;
    this.clientPerformance.set(clientId, {
      ...this.clientPerformance.get(clientId) || {},
      lastMetrics: metrics,
      timestamp: Date.now(),
    });
    return processedUpdate;
  }

  /** Get current global model */
  getGlobalModel() {
    return this._deepCopy(this.globalModel);
  }

  /** Get training statistics */
  getStatistics() {
    const activeClients = Array.from(this.clients.values())
      .filter(client => Date.now() - client.lastActive < 3600000); // Last hour
    return {
      totalRounds: this.currentRound,
      totalClients: this.clients.size,
      activeClients: activeClients.length,
      convergenceCurve: this.convergenceCurve,
      privacyBudgetUsed: this.privacyBudgetUsed,
      clientParticipation: this._calculateClientParticipation(),
      modelMetrics: this.modelMetrics,
    };
  }

  /** Evaluate global model */
  async evaluateGlobalModel(evaluationFunction, validationData) {
    try {
      const metrics = await evaluationFunction(this.globalModel, validationData);
      this.modelMetrics.push({ round: this.currentRound, metrics, timestamp: Date.now() });
      return metrics;
    } catch (error) {
      this._emitEvent('error', { error, context: 'evaluation' });
      throw error;
    }
  }

  /** Export state */
  export() {
    return {
      modelType: this.modelType,
      currentRound: this.currentRound,
      globalModel: this.globalModel,
      clientCount: this.clients.size,
      modelMetrics: this.modelMetrics,
      privacyBudgetUsed: this.privacyBudgetUsed,
      convergenceCurve: this.convergenceCurve,
      version: '1.0.0',
      timestamp: Date.now(),
    };
  }

  /** Import state */
  import(state) {
    if (!state || !state.globalModel) return false;
    this.modelType = state.modelType || this.modelType;
    this.currentRound = state.currentRound || 0;
    this.globalModel = state.globalModel;
    this.previousGlobalModel = this._deepCopy(this.globalModel);
    this.modelMetrics = state.modelMetrics || [];
    this.privacyBudgetUsed = state.privacyBudgetUsed || 0;
    this.convergenceCurve = state.convergenceCurve || [];
    return true;
  }

  // **Private Methods**

  async _executeFederatedRound() {
    const selectedClients = this._selectClients();
    if (selectedClients.length < this.minParticipants) {
      throw new Error('Not enough clients available');
    }

    await Promise.all(selectedClients.map(clientId => this._distributeModelToClient(clientId)));
    const clientUpdates = await this._collectClientUpdates(selectedClients);
    const aggregatedUpdate = await this._aggregateClientUpdates(clientUpdates);

    this.previousGlobalModel = this._deepCopy(this.globalModel);
    this._updateGlobalModel(aggregatedUpdate);

    const convergenceMetric = this._calculateConvergenceMetric();
    this.convergenceCurve.push(convergenceMetric);

    const roundResults = {
      round: this.currentRound,
      clientsParticipated: selectedClients.length,
      convergenceMetric,
      timestamp: Date.now(),
    };
    this._emitEvent('roundComplete', roundResults);
    return roundResults;
  }

  _selectClients() {
    const allClients = Array.from(this.clients.keys());
    const numToSelect = Math.max(
      this.minParticipants,
      Math.floor(allClients.length * this.clientSelectionRatio)
    );
    const shuffled = [...allClients].sort(() => 0.5 - Math.random());
    const selected = shuffled.slice(0, numToSelect);
    selected.forEach(clientId => this.clients.get(clientId).rounds.selected++);
    return selected;
  }

  async _distributeModelToClient(clientId) {
    const client = this.clients.get(clientId);
    client.status = 'training';
    client.lastActive = Date.now();
    return true;
  }

  async _collectClientUpdates(clientIds) {
    return clientIds.map(clientId => {
      const client = this.clients.get(clientId);
      client.status = 'idle';
      client.rounds.participated++;
      const datasetSize = client.datasetSize;
      const weightedContribution = datasetSize / this._getTotalDatasetSize();
      return {
        clientId,
        datasetSize,
        weightedContribution,
        update: this._simulateModelUpdate(),
        timestamp: Date.now(),
      };
    });
  }

  async _aggregateClientUpdates(clientUpdates) {
    let aggregatedUpdate;
    if (this.secureAggregation) {
      aggregatedUpdate = await this._secureAggregate(clientUpdates);
    } else {
      switch (this.aggregationStrategy) {
        case AggregationStrategy.WEIGHTED_AVERAGE:
          aggregatedUpdate = this._weightedAverageAggregation(clientUpdates);
          break;
        case AggregationStrategy.MEDIAN:
          aggregatedUpdate = this._medianAggregation(clientUpdates);
          break;
        case AggregationStrategy.TRIMMED_MEAN:
          aggregatedUpdate = this._trimmedMeanAggregation(clientUpdates);
          break;
        case AggregationStrategy.KRUM:
          aggregatedUpdate = this._krumAggregation(clientUpdates);
          break;
        case AggregationStrategy.COORDMEDIAN:
          aggregatedUpdate = this._coordinateWiseMedianAggregation(clientUpdates);
          break;
        case AggregationStrategy.FEDAVG:
        default:
          aggregatedUpdate = this._fedAvgAggregation(clientUpdates);
          break;
      }
    }

    if (this.privacyMechanism === PrivacyMechanism.DIFFERENTIAL_PRIVACY ||
        this.privacyMechanism === PrivacyMechanism.HYBRID) {
      aggregatedUpdate = this._applyServerDifferentialPrivacy(aggregatedUpdate);
    }
    return aggregatedUpdate;
  }

  _updateGlobalModel(aggregatedUpdate) {
    for (const paramName in this.globalModel) {
      if (Object.prototype.hasOwnProperty.call(this.globalModel, paramName)) {
        if (Array.isArray(this.globalModel[paramName])) {
          this._updateArrayParameter(this.globalModel[paramName], aggregatedUpdate[paramName]);
        } else if (typeof this.globalModel[paramName] === 'number') {
          this.globalModel[paramName] = aggregatedUpdate[paramName];
        } else if (typeof this.globalModel[paramName] === 'object' && this.globalModel[paramName] !== null) {
          this._updateNestedParameters(this.globalModel[paramName], aggregatedUpdate[paramName]);
        }
      }
    }
    this._emitEvent('modelUpdated', { round: this.currentRound, model: this.globalModel });
  }

  _updateArrayParameter(param, update) {
    if (!Array.isArray(update) || param.length !== update.length) {
      throw new Error('Update array dimensions mismatch');
    }
    for (let i = 0; i < param.length; i++) {
      if (Array.isArray(param[i])) {
        this._updateArrayParameter(param[i], update[i]);
      } else {
        param[i] = update[i];
      }
    }
  }

  _updateNestedParameters(param, update) {
    for (const key in update) {
      if (Object.prototype.hasOwnProperty.call(update, key) && param[key] !== undefined) {
        if (Array.isArray(param[key])) {
          this._updateArrayParameter(param[key], update[key]);
        } else if (typeof param[key] === 'number') {
          param[key] = update[key];
        } else if (typeof param[key] === 'object' && param[key] !== null) {
          this._updateNestedParameters(param[key], update[key]);
        }
      }
    }
  }

  _fedAvgAggregation(clientUpdates) {
    const result = this._deepCopy(this.globalModel);
    const totalSize = clientUpdates.reduce((sum, update) => sum + update.datasetSize, 0);
    this._initializeWithZeros(result);
    for (const clientUpdate of clientUpdates) {
      const weight = clientUpdate.datasetSize / totalSize;
      this._addWeightedUpdate(result, clientUpdate.update, weight);
    }
    return result;
  }

  _weightedAverageAggregation(clientUpdates) {
    const result = this._deepCopy(this.globalModel);
    const totalWeight = clientUpdates.reduce((sum, update) => sum + update.weightedContribution, 0);
    this._initializeWithZeros(result);
    for (const clientUpdate of clientUpdates) {
      const normalizedWeight = clientUpdate.weightedContribution / totalWeight;
      this._addWeightedUpdate(result, clientUpdate.update, normalizedWeight);
    }
    return result;
  }

  _medianAggregation(clientUpdates) {
    const result = this._deepCopy(this.globalModel);
    for (const paramName in result) {
      if (Object.prototype.hasOwnProperty.call(result, paramName)) {
        if (Array.isArray(result[paramName])) {
          result[paramName] = this._computeMedianArray(
            clientUpdates.map(update => update.update[paramName])
          );
        } else if (typeof result[paramName] === 'number') {
          result[paramName] = this._computeMedianScalar(
            clientUpdates.map(update => update.update[paramName])
          );
        } else if (typeof result[paramName] === 'object' && result[paramName] !== null) {
          result[paramName] = this._computeMedianObject(
            paramName,
            clientUpdates.map(update => update.update[paramName])
          );
        }
      }
    }
    return result;
  }

  _trimmedMeanAggregation(clientUpdates) {
    const result = this._deepCopy(this.globalModel);
    const trimRatio = 0.1;
    this._initializeWithZeros(result);
    for (const paramName in result) {
      if (Object.prototype.hasOwnProperty.call(result, paramName)) {
        if (Array.isArray(result[paramName])) {
          result[paramName] = this._computeTrimmedMeanArray(
            clientUpdates.map(update => update.update[paramName]),
            trimRatio
          );
        } else if (typeof result[paramName] === 'number') {
          result[paramName] = this._computeTrimmedMeanScalar(
            clientUpdates.map(update => update.update[paramName]),
            trimRatio
          );
        } else if (typeof result[paramName] === 'object' && result[paramName] !== null) {
          result[paramName] = this._computeTrimmedMeanObject(
            paramName,
            clientUpdates.map(update => update.update[paramName]),
            trimRatio
          );
        }
      }
    }
    return result;
  }

  _krumAggregation(clientUpdates) {
    if (clientUpdates.length <= 2) return this._fedAvgAggregation(clientUpdates);
    const f = Math.floor((clientUpdates.length - 1) / 2) - 1;
    if (f <= 0) return this._fedAvgAggregation(clientUpdates);

    const distances = this._computeUpdateDistances(clientUpdates);
    const scores = clientUpdates.map((_, i) => {
      const sortedDistances = [...distances[i]].sort((a, b) => a - b);
      return sortedDistances.slice(1, clientUpdates.length - f).reduce((sum, d) => sum + d, 0);
    });
    const minIndex = scores.indexOf(Math.min(...scores));
    return clientUpdates[minIndex].update;
  }

  _coordinateWiseMedianAggregation(clientUpdates) {
    const result = this._deepCopy(this.globalModel);
    for (const paramName in result) {
      if (Object.prototype.hasOwnProperty.call(result, paramName)) {
        if (Array.isArray(result[paramName])) {
          result[paramName] = this._applyCoordinateWiseMedian(
            clientUpdates.map(update => update.update[paramName])
          );
        } else if (typeof result[paramName] === 'number') {
          result[paramName] = this._computeMedianScalar(
            clientUpdates.map(update => update.update[paramName])
          );
        } else if (typeof result[paramName] === 'object' && result[paramName] !== null) {
          result[paramName] = this._applyCoordinateWiseMedianObject(
            paramName,
            clientUpdates.map(update => update.update[paramName])
          );
        }
      }
    }
    return result;
  }

  async _secureAggregate(clientUpdates) {
    const shares = await Promise.all(clientUpdates.map(clientUpdate =>
      this.secretSharing.createShares(
        clientUpdate.update,
        clientUpdates.length,
        Math.ceil(clientUpdates.length / 2)
      )
    ));
    const aggregatedShares = this._aggregateShares(shares);
    return await this.secretSharing.reconstructSecret(aggregatedShares);
  }

  _applyClientPrivacy(update) {
    const clippedUpdate = this._clipGradient(update, this.clippingThreshold);
    if (this.privacyMechanism === PrivacyMechanism.DIFFERENTIAL_PRIVACY) {
      return this._addLaplaceNoise(clippedUpdate, this.epsilon / 2);
    }
    return clippedUpdate;
  }

  _applyServerDifferentialPrivacy(aggregatedUpdate) {
    const sensitivity = this.clippingThreshold;
    const result = this._addGaussianNoise(aggregatedUpdate, sensitivity * this.noiseScale);
    this._updatePrivacyBudget();
    return result;
  }

  _clipGradient(update, threshold) {
    const result = this._deepCopy(update);
    const norm = this._calculateL2Norm(update);
    if (norm > threshold) {
      const scalingFactor = threshold / norm;
      this._scaleUpdate(result, scalingFactor);
    }
    return result;
  }

  _addLaplaceNoise(update, epsilon) {
    const result = this._deepCopy(update);
    const scale = 1.0 / epsilon;
    this._traverseAndAddNoise(result, value => {
      const u = Math.random() - 0.5;
      return value - Math.sign(u) * scale * Math.log(1 - 2 * Math.abs(u));
    });
    return result;
  }

  _addGaussianNoise(update, sigma) {
    const result = this._deepCopy(update);
    this._traverseAndAddNoise(result, value => {
      const u1 = Math.random();
      const u2 = Math.random();
      return value + sigma * Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    });
    return result;
  }

  _traverseAndAddNoise(obj, noiseFn) {
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        if (Array.isArray(obj[key])) {
          for (let i = 0; i < obj[key].length; i++) {
            if (Array.isArray(obj[key][i])) {
              this._traverseAndAddNoise(obj[key][i], noiseFn);
            } else if (typeof obj[key][i] === 'number') {
              obj[key][i] = noiseFn(obj[key][i]);
            }
          }
        } else if (typeof obj[key] === 'number') {
          obj[key] = noiseFn(obj[key]);
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          this._traverseAndAddNoise(obj[key], noiseFn);
        }
      }
    }
  }

  _calculateL2Norm(update) {
    let sumSquares = 0;
    const traverse = obj => {
      for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          if (Array.isArray(obj[key])) {
            for (let i = 0; i < obj[key].length; i++) {
              if (Array.isArray(obj[key][i])) traverse(obj[key][i]);
              else if (typeof obj[key][i] === 'number') sumSquares += obj[key][i] ** 2;
            }
          } else if (typeof obj[key] === 'number') {
            sumSquares += obj[key] ** 2;
          } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            traverse(obj[key]);
          }
        }
      }
    };
    traverse(update);
    return Math.sqrt(sumSquares);
  }

  _scaleUpdate(update, factor) {
    const traverse = obj => {
      for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          if (Array.isArray(obj[key])) {
            for (let i = 0; i < obj[key].length; i++) {
              if (Array.isArray(obj[key][i])) traverse(obj[key][i]);
              else if (typeof obj[key][i] === 'number') obj[key][i] *= factor;
            }
          } else if (typeof obj[key] === 'number') {
            obj[key] *= factor;
          } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            traverse(obj[key]);
          }
        }
      }
    };
    traverse(update);
  }

  _calculateInitialNoiseScale() {
    if (this.privacyMechanism === PrivacyMechanism.DIFFERENTIAL_PRIVACY) {
      const c = Math.sqrt(2 * Math.log(1.25 / this.delta));
      return c / this.epsilon;
    }
    return 1.0;
  }

  _updatePrivacyBudget() {
    if (this.privacyMechanism === PrivacyMechanism.DIFFERENTIAL_PRIVACY) {
      this.privacyBudgetUsed += this.epsilon / this.numRounds;
      if (this.adaptiveClipping) this._adaptNoiseScale();
    }
  }

  _adaptNoiseScale() {
    const trend = this._analyzeConvergenceTrend();
    if (trend === 'fast') this.noiseScale *= 1.05;
    else if (trend === 'slow' && this.privacyBudgetUsed < 0.5 * this.epsilon) this.noiseScale *= 0.95;
  }

  _analyzeConvergenceTrend() {
    if (this.convergenceCurve.length < 3) return 'steady';
    const recent = this.convergenceCurve.slice(-3);
    const deltas = [recent[1] - recent[0], recent[2] - recent[1]];
    if (deltas[0] < 0 && deltas[1] < 0 && Math.abs(deltas[1]) < Math.abs(deltas[0]) * 0.5) return 'fast';
    if (deltas[0] >= 0 || deltas[1] >= 0) return 'slow';
    return 'steady';
  }

  _checkConvergence() {
    if (this.convergenceTest) return this.convergenceTest(this.globalModel, this.previousGlobalModel, this.currentRound);
    if (this.convergenceCurve.length < 2) return false;
    const threshold = 1e-4;
    const latest = this.convergenceCurve[this.convergenceCurve.length - 1];
    const previous = this.convergenceCurve[this.convergenceCurve.length - 2];
    return Math.abs(latest - previous) < threshold;
  }

  _calculateConvergenceMetric() {
    let sumSquaredDiff = 0, count = 0;
    const traverse = (current, previous) => {
      for (const key in current) {
        if (Object.prototype.hasOwnProperty.call(current, key) && Object.prototype.hasOwnProperty.call(previous, key)) {
          if (Array.isArray(current[key]) && Array.isArray(previous[key])) {
            for (let i = 0; i < current[key].length; i++) {
              if (Array.isArray(current[key][i])) traverse(current[key][i], previous[key][i]);
              else if (typeof current[key][i] === 'number' && typeof previous[key][i] === 'number') {
                const diff = current[key][i] - previous[key][i];
                sumSquaredDiff += diff * diff;
                count++;
              }
            }
          } else if (typeof current[key] === 'number' && typeof previous[key] === 'number') {
            const diff = current[key] - previous[key];
            sumSquaredDiff += diff * diff;
            count++;
          } else if (typeof current[key] === 'object' && current[key] !== null) {
            traverse(current[key], previous[key]);
          }
        }
      }
    };
    traverse(this.globalModel, this.previousGlobalModel);
    return count > 0 ? Math.sqrt(sumSquaredDiff / count) : 0;
  }

  _initializeWithZeros(obj) {
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        if (Array.isArray(obj[key])) this._initializeArrayWithZeros(obj[key]);
        else if (typeof obj[key] === 'number') obj[key] = 0;
        else if (typeof obj[key] === 'object' && obj[key] !== null) this._initializeWithZeros(obj[key]);
      }
    }
  }

  _initializeArrayWithZeros(arr) {
    for (let i = 0; i < arr.length; i++) {
      if (Array.isArray(arr[i])) this._initializeArrayWithZeros(arr[i]);
      else if (typeof arr[i] === 'number') arr[i] = 0;
      else if (typeof arr[i] === 'object' && arr[i] !== null) this._initializeWithZeros(arr[i]);
    }
  }

  _addWeightedUpdate(result, update, weight) {
    for (const key in update) {
      if (Object.prototype.hasOwnProperty.call(update, key) && Object.prototype.hasOwnProperty.call(result, key)) {
        if (Array.isArray(result[key])) {
          this._addWeightedArrayUpdate(result[key], update[key], weight);
        } else if (typeof result[key] === 'number') {
          result[key] += update[key] * weight;
        } else if (typeof result[key] === 'object' && result[key] !== null) {
          this._addWeightedUpdate(result[key], update[key], weight);
        }
      }
    }
  }

  _addWeightedArrayUpdate(resultArr, updateArr, weight) {
    for (let i = 0; i < resultArr.length && i < updateArr.length; i++) {
      if (Array.isArray(resultArr[i])) {
        this._addWeightedArrayUpdate(resultArr[i], updateArr[i], weight);
      } else if (typeof resultArr[i] === 'number') {
        resultArr[i] += updateArr[i] * weight;
      } else if (typeof resultArr[i] === 'object' && resultArr[i] !== null) {
        this._addWeightedUpdate(resultArr[i], updateArr[i], weight);
      }
    }
  }

  _computeMedianScalar(values) {
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
  }

  _computeMedianArray(arrays) {
    if (arrays.length === 0) return [];
    const result = Array(arrays[0].length);
    for (let i = 0; i < arrays[0].length; i++) {
      if (Array.isArray(arrays[0][i])) {
        const nestedArrays = arrays.map(arr => arr[i]);
        result[i] = this._computeMedianArray(nestedArrays);
      } else if (typeof arrays[0][i] === 'number') {
        result[i] = this._computeMedianScalar(arrays.map(arr => arr[i]));
      } else {
        result[i] = arrays[0][i];
      }
    }
    return result;
  }

  _computeMedianObject(objName, objects) {
    if (objects.length === 0) return {};
    const result = {};
    for (const key in objects[0]) {
      if (Object.prototype.hasOwnProperty.call(objects[0], key)) {
        if (Array.isArray(objects[0][key])) {
          result[key] = this._computeMedianArray(objects.map(obj => obj[key]));
        } else if (typeof objects[0][key] === 'number') {
          result[key] = this._computeMedianScalar(objects.map(obj => obj[key]));
        } else if (typeof objects[0][key] === 'object' && objects[0][key] !== null) {
          result[key] = this._computeMedianObject(`${objName}.${key}`, objects.map(obj => obj[key]));
        } else {
          result[key] = objects[0][key];
        }
      }
    }
    return result;
  }

  _computeTrimmedMeanScalar(values, trimRatio) {
    const sorted = [...values].sort((a, b) => a - b);
    const trimCount = Math.floor(sorted.length * trimRatio);
    const trimmed = sorted.slice(trimCount, sorted.length - trimCount);
    return trimmed.length === 0 ? sorted[Math.floor(sorted.length / 2)] :
      trimmed.reduce((sum, val) => sum + val, 0) / trimmed.length;
  }

  _computeTrimmedMeanArray(arrays, trimRatio) {
    if (arrays.length === 0) return [];
    const result = Array(arrays[0].length);
    for (let i = 0; i < arrays[0].length; i++) {
      if (Array.isArray(arrays[0][i])) {
        result[i] = this._computeTrimmedMeanArray(arrays.map(arr => arr[i]), trimRatio);
      } else if (typeof arrays[0][i] === 'number') {
        result[i] = this._computeTrimmedMeanScalar(arrays.map(arr => arr[i]), trimRatio);
      } else {
        result[i] = arrays[0][i];
      }
    }
    return result;
  }

  _computeTrimmedMeanObject(objName, objects, trimRatio) {
    if (objects.length === 0) return {};
    const result = {};
    for (const key in objects[0]) {
      if (Object.prototype.hasOwnProperty.call(objects[0], key)) {
        if (Array.isArray(objects[0][key])) {
          result[key] = this._computeTrimmedMeanArray(objects.map(obj => obj[key]), trimRatio);
        } else if (typeof objects[0][key] === 'number') {
          result[key] = this._computeTrimmedMeanScalar(objects.map(obj => obj[key]), trimRatio);
        } else if (typeof objects[0][key] === 'object' && objects[0][key] !== null) {
          result[key] = this._computeTrimmedMeanObject(`${objName}.${key}`, objects.map(obj => obj[key]), trimRatio);
        } else {
          result[key] = objects[0][key];
        }
      }
    }
    return result;
  }

  _applyCoordinateWiseMedian(arrays) {
    if (arrays.length === 0) return [];
    const result = Array(arrays[0].length);
    for (let i = 0; i < arrays[0].length; i++) {
      if (Array.isArray(arrays[0][i])) {
        result[i] = this._applyCoordinateWiseMedian(arrays.map(arr => arr[i]));
      } else if (typeof arrays[0][i] === 'number') {
        result[i] = this._computeMedianScalar(arrays.map(arr => arr[i]));
      } else {
        result[i] = arrays[0][i];
      }
    }
    return result;
  }

  _applyCoordinateWiseMedianObject(objName, objects) {
    if (objects.length === 0) return {};
    const result = {};
    for (const key in objects[0]) {
      if (Object.prototype.hasOwnProperty.call(objects[0], key)) {
        if (Array.isArray(objects[0][key])) {
          result[key] = this._applyCoordinateWiseMedian(objects.map(obj => obj[key]));
        } else if (typeof objects[0][key] === 'number') {
          result[key] = this._computeMedianScalar(objects.map(obj => obj[key]));
        } else if (typeof objects[0][key] === 'object' && objects[0][key] !== null) {
          result[key] = this._applyCoordinateWiseMedianObject(`${objName}.${key}`, objects.map(obj => obj[key]));
        } else {
          result[key] = objects[0][key];
        }
      }
    }
    return result;
  }

  _computeUpdateDistances(clientUpdates) {
    const n = clientUpdates.length;
    const distances = Array(n).fill().map(() => Array(n).fill(0));
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const distance = this._computeDistance(clientUpdates[i].update, clientUpdates[j].update);
        distances[i][j] = distances[j][i] = distance;
      }
    }
    return distances;
  }

  _computeDistance(update1, update2) {
    let sumSquaredDiff = 0;
    const traverse = (obj1, obj2) => {
      for (const key in obj1) {
        if (Object.prototype.hasOwnProperty.call(obj1, key) && Object.prototype.hasOwnProperty.call(obj2, key)) {
          if (Array.isArray(obj1[key])) {
            for (let i = 0; i < obj1[key].length && i < obj2[key].length; i++) {
              if (Array.isArray(obj1[key][i])) traverse(obj1[key][i], obj2[key][i]);
              else if (typeof obj1[key][i] === 'number') {
                const diff = obj1[key][i] - obj2[key][i];
                sumSquaredDiff += diff * diff;
              }
            }
          } else if (typeof obj1[key] === 'number') {
            const diff = obj1[key] - obj2[key];
            sumSquaredDiff += diff * diff;
          } else if (typeof obj1[key] === 'object' && obj1[key] !== null) {
            traverse(obj1[key], obj2[key]);
          }
        }
      }
    };
    traverse(update1, update2);
    return Math.sqrt(sumSquaredDiff);
  }

  _aggregateShares(shares) {
    if (shares.length === 0 || shares[0].length === 0) return [];
    const aggregated = [];
    const numShares = shares[0].length;
    for (let i = 0; i < numShares; i++) {
      aggregated.push(shares.map(clientShares => clientShares[i]));
    }
    return aggregated;
  }

  _getTotalDatasetSize() {
    return Array.from(this.clients.values()).reduce((sum, client) => sum + client.datasetSize, 0);
  }

  _calculateClientParticipation() {
    const clients = Array.from(this.clients.values());
    const totalRounds = this.currentRound;
    const participationRates = clients.map(client => ({
      clientId: client.id,
      participated: client.rounds.participated,
      selected: client.rounds.selected,
      participationRate: totalRounds > 0 ? client.rounds.participated / totalRounds : 0,
      selectionRate: totalRounds > 0 ? client.rounds.selected / totalRounds : 0,
    }));
    const avgParticipationRate = participationRates.reduce((sum, client) => sum + client.participationRate, 0) / clients.length;
    return { totalClients: clients.length, totalRounds, participationRates, avgParticipationRate };
  }

  _simulateModelUpdate() {
    const update = this._deepCopy(this.globalModel);
    const perturb = obj => {
      for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          if (Array.isArray(obj[key])) {
            for (let i = 0; i < obj[key].length; i++) {
              if (Array.isArray(obj[key][i])) perturb(obj[key][i]);
              else if (typeof obj[key][i] === 'number') obj[key][i] += (Math.random() - 0.5) * 0.1;
            }
          } else if (typeof obj[key] === 'number') {
            obj[key] += (Math.random() - 0.5) * 0.1;
          } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            perturb(obj[key]);
          }
        }
      }
    };
    perturb(update);
    return update;
  }

  _deepCopy(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  _emitEvent(event, data) {
    if (!this.eventListeners[event]) return;
    for (const callback of this.eventListeners[event]) {
      try {
        callback(data);
      } catch (error) {
        console.error(`Error in ${event} listener:`, error);
      }
    }
  }
}

/**
 * ### FederatedClient Class
 * Client-side implementation for federated learning.
 */
class FederatedClient {
  constructor(options = {}) {
    this.clientId = options.clientId || crypto.randomBytes(16).toString('hex');
    this.localData = options.localData || [];
    this.localLabels = options.localLabels || [];
    this.validationSplit = options.validationSplit || 0.1;
    this.batchSize = options.batchSize || 32;
    this.epochs = options.epochs || 5;
    this.learningRate = options.learningRate || 0.01;
    this.differentialPrivacy = options.differentialPrivacy || false;
    this.epsilon = options.epsilon || 1.0;
    this.clippingThreshold = options.clippingThreshold || 1.0;
    this.globalModel = null;
    this.localModel = null;
    this.optimizer = null;
    this.initialModelParams = null;
    this.trainingMetrics = [];
    this.currentRound = 0;
    this.connectionStatus = 'disconnected';
    this._splitDataset();
  }

  async connect(serverUrl) {
    try {
      this.serverUrl = serverUrl;
      this.connectionStatus = 'connected';
      await this._registerWithServer();
      return true;
    } catch (error) {
      this.connectionStatus = 'error';
      console.error('Connection error:', error);
      return false;
    }
  }

  receiveGlobalModel(globalModel) {
    this.globalModel = this._deepCopy(globalModel);
    this.initialModelParams = this._deepCopy(globalModel);
    this._initializeLocalModel();
    return true;
  }

  async trainLocalModel() {
    if (!this.localModel) throw new Error('Local model not initialized');
    const startTime = Date.now();
    const metrics = {
      clientId: this.clientId,
      round: this.currentRound,
      epochs: this.epochs,
      batchesProcessed: 0,
      initialLoss: await this._evaluateModel(),
      finalLoss: 0,
      trainingTime: 0,
    };

    try {
      for (let epoch = 0; epoch < this.epochs; epoch++) {
        const epochMetrics = await this._trainEpoch();
        metrics.batchesProcessed += epochMetrics.batchesProcessed;
      }
      metrics.finalLoss = await this._evaluateModel();
      metrics.trainingTime = Date.now() - startTime;
      this.trainingMetrics.push(metrics);
      return metrics;
    } catch (error) {
      console.error('Training error:', error);
      throw error;
    }
  }

  computeModelUpdate() {
    if (!this.localModel || !this.initialModelParams) {
      throw new Error('Model not initialized or no initial parameters');
    }
    const localParams = this._extractModelParameters();
    const modelUpdate = this._computeParameterDifference(localParams, this.initialModelParams);
    return this.differentialPrivacy ? this._applyDifferentialPrivacy(modelUpdate) : modelUpdate;
  }

  async sendModelUpdate(update) {
    try {
      const updateWithMetadata = {
        clientId: this.clientId,
        round: this.currentRound,
        datasetSize: this.trainingData.length,
        update,
        metrics: this.trainingMetrics[this.trainingMetrics.length - 1],
        timestamp: Date.now(),
      };
      console.log(`Client ${this.clientId} sending update for round ${this.currentRound}`);
      this.currentRound++;
      return true;
    } catch (error) {
      console.error('Error sending update:', error);
      return false;
    }
  }

  async evaluateModel() {
    return this._evaluateModel();
  }

  getMetrics() {
    return this.trainingMetrics;
  }

  // **Private Methods**

  async _registerWithServer() {
    const registrationData = {
      clientId: this.clientId,
      datasetSize: this.localData.length,
      features: this._getFeatureDescription(),
      capabilities: { batchSize: this.batchSize, maxEpochs: this.epochs, differentialPrivacy: this.differentialPrivacy },
    };
    return true;
  }

  _initializeLocalModel() {
    this.localModel = this._deepCopy(this.globalModel);
    this.optimizer = { learningRate: this.learningRate, momentum: 0.9 };
  }

  async _trainEpoch() {
    const metrics = { batchesProcessed: 0, losses: [] };
    const batches = this._createBatches(this.trainingData, this.trainingLabels);
    for (const batch of batches) {
      const batchLoss = await this._processBatch(batch.data, batch.labels);
      metrics.losses.push(batchLoss);
      metrics.batchesProcessed++;
    }
    return metrics;
  }

  async _processBatch(batchData, batchLabels) {
    const predictions = this._forwardPass(batchData);
    const initialLoss = this._calculateLoss(predictions, batchLabels);
    const gradients = this._calculateGradients(predictions, batchLabels);
    this._updateParameters(gradients);
    const newPredictions = this._forwardPass(batchData);
    return this._calculateLoss(newPredictions, batchLabels);
  }

  _forwardPass(data) {
    return data.map(() => Math.random());
  }

  _calculateLoss(predictions, labels) {
    let sumSquaredError = 0;
    for (let i = 0; i < predictions.length; i++) {
      if (Array.isArray(predictions[i])) {
        for (let j = 0; j < predictions[i].length; j++) {
          const error = predictions[i][j] - labels[i][j];
          sumSquaredError += error * error;
        }
      } else {
        const error = predictions[i] - labels[i];
        sumSquaredError += error * error;
      }
    }
    return sumSquaredError / predictions.length;
  }

  _calculateGradients(predictions, labels) {
    const gradients = this._deepCopy(this.localModel);
    const applyRandom = obj => {
      for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          if (Array.isArray(obj[key])) {
            for (let i = 0; i < obj[key].length; i++) {
              if (Array.isArray(obj[key][i])) applyRandom(obj[key][i]);
              else if (typeof obj[key][i] === 'number') obj[key][i] = (Math.random() - 0.5) * 0.01;
            }
          } else if (typeof obj[key] === 'number') {
            obj[key] = (Math.random() - 0.5) * 0.01;
          } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            applyRandom(obj[key]);
          }
        }
      }
    };
    applyRandom(gradients);
    if (this.differentialPrivacy) this._clipGradients(gradients, this.clippingThreshold);
    return gradients;
  }

  _updateParameters(gradients) {
    const apply = (params, grads) => {
      for (const key in params) {
        if (Object.prototype.hasOwnProperty.call(params, key) && Object.prototype.hasOwnProperty.call(grads, key)) {
          if (Array.isArray(params[key])) {
            for (let i = 0; i < params[key].length; i++) {
              if (Array.isArray(params[key][i])) apply(params[key][i], grads[key][i]);
              else if (typeof params[key][i] === 'number') params[key][i] -= this.optimizer.learningRate * grads[key][i];
            }
          } else if (typeof params[key] === 'number') {
            params[key] -= this.optimizer.learningRate * grads[key];
          } else if (typeof params[key] === 'object' && params[key] !== null) {
            apply(params[key], grads[key]);
          }
        }
      }
    };
    apply(this.localModel, gradients);
  }

  async _evaluateModel() {
    if (!this.localModel || this.validationData.length === 0) return Infinity;
    const predictions = this._forwardPass(this.validationData);
    return this._calculateLoss(predictions, this.validationLabels);
  }

  _extractModelParameters() {
    return this._deepCopy(this.localModel);
  }

  _computeParameterDifference(currentParams, initialParams) {
    const diff = this._deepCopy(currentParams);
    const compute = (current, initial, result) => {
      for (const key in current) {
        if (Object.prototype.hasOwnProperty.call(current, key) && Object.prototype.hasOwnProperty.call(initial, key)) {
          if (Array.isArray(current[key])) {
            for (let i = 0; i < current[key].length; i++) {
              if (Array.isArray(current[key][i])) compute(current[key][i], initial[key][i], result[key][i]);
              else if (typeof current[key][i] === 'number') result[key][i] = current[key][i] - initial[key][i];
            }
          } else if (typeof current[key] === 'number') {
            result[key] = current[key] - initial[key];
          } else if (typeof current[key] === 'object' && current[key] !== null) {
            compute(current[key], initial[key], result[key]);
          }
        }
      }
    };
    compute(currentParams, initialParams, diff);
    return diff;
  }

  _applyDifferentialPrivacy(update) {
    const clippedUpdate = this._clipGradients(update, this.clippingThreshold);
    return this._addLaplaceNoise(clippedUpdate, this.epsilon);
  }

  _clipGradients(gradients, threshold) {
    const norm = this._calculateL2Norm(gradients);
    if (norm <= threshold) return gradients;
    const scalingFactor = threshold / norm;
    this._scaleGradients(gradients, scalingFactor);
    return gradients;
  }

  _calculateL2Norm(gradients) {
    let sumSquares = 0;
    const traverse = obj => {
      for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          if (Array.isArray(obj[key])) {
            for (let i = 0; i < obj[key].length; i++) {
              if (Array.isArray(obj[key][i])) traverse(obj[key][i]);
              else if (typeof obj[key][i] === 'number') sumSquares += obj[key][i] ** 2;
            }
          } else if (typeof obj[key] === 'number') {
            sumSquares += obj[key] ** 2;
          } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            traverse(obj[key]);
          }
        }
      }
    };
    traverse(gradients);
    return Math.sqrt(sumSquares);
  }

  _scaleGradients(gradients, factor) {
    const traverse = obj => {
      for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          if (Array.isArray(obj[key])) {
            for (let i = 0; i < obj[key].length; i++) {
              if (Array.isArray(obj[key][i])) traverse(obj[key][i]);
              else if (typeof obj[key][i] === 'number') obj[key][i] *= factor;
            }
          } else if (typeof obj[key] === 'number') {
            obj[key] *= factor;
          } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            traverse(obj[key]);
          }
        }
      }
    };
    traverse(gradients);
  }

  _addLaplaceNoise(obj, epsilon) {
    const result = this._deepCopy(obj);
    const scale = 1.0 / epsilon;
    const traverse = o => {
      for (const key in o) {
        if (Object.prototype.hasOwnProperty.call(o, key)) {
          if (Array.isArray(o[key])) {
            for (let i = 0; i < o[key].length; i++) {
              if (Array.isArray(o[key][i])) traverse(o[key][i]);
              else if (typeof o[key][i] === 'number') {
                const u = Math.random() - 0.5;
                o[key][i] += -Math.sign(u) * scale * Math.log(1 - 2 * Math.abs(u));
              }
            }
          } else if (typeof o[key] === 'number') {
            const u = Math.random() - 0.5;
            o[key] += -Math.sign(u) * scale * Math.log(1 - 2 * Math.abs(u));
          } else if (typeof o[key] === 'object' && o[key] !== null) {
            traverse(o[key]);
          }
        }
      }
    };
    traverse(result);
    return result;
  }

  _createBatches(data, labels) {
    const batches = [];
    const indices = Array.from({ length: data.length }, (_, i) => i);
    this._shuffleArray(indices);
    for (let i = 0; i < indices.length; i += this.batchSize) {
      const batchIndices = indices.slice(i, i + this.batchSize);
      batches.push({
        data: batchIndices.map(idx => data[idx]),
        labels: batchIndices.map(idx => labels[idx]),
      });
    }
    return batches;
  }

  _shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [array[i], array[j]] = [array[j], array[i]];
    }
  }

  _splitDataset() {
    if (this.localData.length === 0) {
      this.trainingData = [];
      this.trainingLabels = [];
      this.validationData = [];
      this.validationLabels = [];
      return;
    }
    const indices = Array.from({ length: this.localData.length }, (_, i) => i);
    this._shuffleArray(indices);
    const splitPoint = Math.floor(this.localData.length * (1 - this.validationSplit));
    this.trainingData = indices.slice(0, splitPoint).map(idx => this.localData[idx]);
    this.trainingLabels = indices.slice(0, splitPoint).map(idx => this.localLabels[idx]);
    this.validationData = indices.slice(splitPoint).map(idx => this.localData[idx]);
    this.validationLabels = indices.slice(splitPoint).map(idx => this.localLabels[idx]);
  }

  _getFeatureDescription() {
    if (this.localData.length === 0) return [];
    const firstExample = this.localData[0];
    return Array.isArray(firstExample) ?
      Array.from({ length: firstExample.length }, (_, i) => `feature_${i}`) : ['scalar'];
  }

  _deepCopy(obj) {
    return JSON.parse(JSON.stringify(obj));
  }
}

// **Exports**
module.exports = {
  FederatedLearning,
  FederatedClient,
  AggregationStrategy,
  ModelType,
  PrivacyMechanism,
};
