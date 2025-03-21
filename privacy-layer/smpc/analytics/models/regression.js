/**
 * PrivaSight Privacy-Preserving Regression
 *
 * This module implements various privacy-preserving regression techniques,
 * allowing machine learning models to be trained collaboratively on distributed
 * datasets without revealing sensitive information. It combines secure
 * multi-party computation, differential privacy, and federated learning
 * approaches to protect data privacy while maintaining model quality.
 */

const { BigNumber } = require('ethers');
const { randomFieldElement } = require('../../zkp/utils/hash');
const { SecretSharing } = require('../../smpc/secret-sharing');
const logger = require('../../../utils/logger')('privacy-layer:regression');

// Regression model types
const RegressionType = {
  LINEAR: 'linear',
  LOGISTIC: 'logistic',
  RIDGE: 'ridge',
  LASSO: 'lasso',
  POLYNOMIAL: 'polynomial',
  QUANTILE: 'quantile'
};

/**
 * Privacy-preserving regression implementation
 * @class RegressionModel
 */
class RegressionModel {
  /**
   * Create a new Privacy-Preserving Regression Model
   * @param {Object} options - Configuration options
   * @param {string} [options.type=RegressionType.LINEAR] - Regression type
   * @param {string} [options.iterativeMethod='gradient_descent'] - Method for iterative models
   * @param {boolean} [options.enableDP=true] - Enable differential privacy
   * @param {number} [options.epsilon=1.0] - Epsilon value for differential privacy
   * @param {number} [options.delta=1e-6] - Delta value for differential privacy
   * @param {Object} [options.dpOptions] - Additional DP options
   * @param {boolean} [options.secureLearningRate=true] - Whether to use secure learning rate
   * @param {Object} [options.iterationOptions] - Options for iterative training
   */
  constructor({
    type = RegressionType.LINEAR,
    iterativeMethod = 'gradient_descent',
    enableDP = true,
    epsilon = 1.0,
    delta = 1e-6,
    dpOptions = {},
    secureLearningRate = true,
    iterationOptions = {
      maxIterations: 100,
      convergenceThreshold: 1e-4,
      learningRate: 0.01,
      batchSize: 32
    }
  } = {}) {
    this.type = type;
    this.iterativeMethod = iterativeMethod;
    this.enableDP = enableDP;
    this.epsilon = epsilon;
    this.delta = delta;
    this.dpOptions = {
      mechanism: 'laplace',
      sensitivity: 2.0,
      clippingThreshold: 1.0,
      ...dpOptions
    };
    this.secureLearningRate = secureLearningRate;
    this.iterationOptions = iterationOptions;

    // Initialize helper components
    this.secretSharing = new SecretSharing();

    // Model parameters
    this.coefficients = null;
    this.intercept = null;
    this.isInitialized = false;
    this.isTrained = false;

    // Training metrics
    this.metrics = {
      iterations: 0,
      error: Infinity,
      privacyBudgetUsed: 0,
      trainingTime: 0,
      convergenceHistory: []
    };

    logger.info(`Initialized privacy-preserving ${type} regression model`);
  }

  /**
   * Initialize the model with random or specified parameters
   * @param {Object} options - Initialization options
   * @param {number} options.numFeatures - Number of features in the dataset
   * @param {Array<number>} [options.initialCoefficients] - Initial coefficient values
   * @param {number} [options.initialIntercept] - Initial intercept value
   * @returns {Promise<Object>} Initialized model parameters
   */
  async initialize({ numFeatures, initialCoefficients, initialIntercept }) {
    try {
      logger.info(`Initializing ${this.type} regression model with ${numFeatures} features`);

      if (!numFeatures || numFeatures <= 0) {
        throw new Error('Number of features must be positive');
      }

      if (initialCoefficients && initialCoefficients.length === numFeatures) {
        this.coefficients = [...initialCoefficients];
      } else {
        this.coefficients = Array(numFeatures).fill(0).map(() => this._generateInitialWeight());
      }

      this.intercept = initialIntercept !== undefined ? initialIntercept : this._generateInitialWeight();
      this.isInitialized = true;

      logger.info(`Model initialized with ${numFeatures} coefficients`);
      return { coefficients: this.coefficients, intercept: this.intercept, numFeatures };
    } catch (error) {
      logger.error('Model initialization failed:', error);
      throw new Error(`Model initialization failed: ${error.message}`);
    }
  }

  /**
   * Train the model using privacy-preserving techniques
   * @param {Object} options - Training options
   * @param {Array<Array<number>>} options.data - Training data features
   * @param {Array<number>} options.labels - Training data labels
   * @param {Object} [options.privacyParameters] - Privacy parameters
   * @param {Array<number>} [options.weights] - Observation weights
   * @param {Object} [options.validationData] - Validation data for early stopping
   * @param {Function} [options.progressCallback] - Callback for training progress
   * @returns {Promise<Object>} Trained model parameters
   */
  async train({
    data,
    labels,
    privacyParameters = {},
    weights = null,
    validationData = null,
    progressCallback = null
  }) {
    try {
      const startTime = Date.now();
      logger.info(`Training ${this.type} regression model with ${data.length} samples`);

      if (!Array.isArray(data) || data.length === 0) {
        throw new Error('Training data must be a non-empty array');
      }
      if (!Array.isArray(labels) || labels.length !== data.length) {
        throw new Error('Labels must have the same length as training data');
      }

      if (!this.isInitialized) {
        await this.initialize({ numFeatures: data[0].length });
      }

      const trainPrivacyParams = {
        epsilon: privacyParameters.epsilon || this.epsilon,
        delta: privacyParameters.delta || this.delta,
        mechanism: privacyParameters.mechanism || this.dpOptions.mechanism,
        sensitivity: privacyParameters.sensitivity || this.dpOptions.sensitivity,
        clippingThreshold: privacyParameters.clippingThreshold || this.dpOptions.clippingThreshold
      };

      switch (this.type) {
        case RegressionType.LINEAR:
          await this._trainLinearRegression(data, labels, weights, trainPrivacyParams);
          break;
        case RegressionType.LOGISTIC:
          await this._trainLogisticRegression(data, labels, weights, trainPrivacyParams);
          break;
        case RegressionType.RIDGE:
          await this._trainRidgeRegression(data, labels, weights, trainPrivacyParams);
          break;
        case RegressionType.LASSO:
          await this._trainLassoRegression(data, labels, weights, trainPrivacyParams);
          break;
        case RegressionType.POLYNOMIAL:
          await this._trainPolynomialRegression(data, labels, weights, trainPrivacyParams);
          break;
        case RegressionType.QUANTILE:
          await this._trainQuantileRegression(data, labels, weights, trainPrivacyParams);
          break;
        default:
          throw new Error(`Unsupported regression type: ${this.type}`);
      }

      this.isTrained = true;
      this.metrics.trainingTime = Date.now() - startTime;

      logger.info(`Training completed in ${this.metrics.trainingTime}ms after ${this.metrics.iterations} iterations`);
      return { coefficients: this.coefficients, intercept: this.intercept, metrics: this.metrics };
    } catch (error) {
      logger.error('Training failed:', error);
      throw new Error(`Training failed: ${error.message}`);
    }
  }

  /**
   * Make predictions using the trained model
   * @param {Array<Array<number>>} data - Features to predict
   * @param {Object} [options] - Prediction options
   * @param {boolean} [options.addNoise=false] - Add noise for privacy
   * @returns {Promise<Array<number>>} Predicted values
   */
  async predict(data, { addNoise = false } = {}) {
    try {
      logger.info(`Predicting for ${data.length} samples`);

      if (!Array.isArray(data) || data.length === 0) {
        throw new Error('Prediction data must be a non-empty array');
      }
      if (!this.isTrained) {
        throw new Error('Model must be trained');
      }

      let predictions;
      switch (this.type) {
        case RegressionType.LINEAR:
        case RegressionType.RIDGE:
        case RegressionType.LASSO:
        case RegressionType.POLYNOMIAL:
          predictions = this._predictLinearModel(data);
          break;
        case RegressionType.LOGISTIC:
          predictions = this._predictLogisticModel(data);
          break;
        case RegressionType.QUANTILE:
          predictions = this._predictQuantileModel(data);
          break;
        default:
          throw new Error(`Unsupported regression type: ${this.type}`);
      }

      if (addNoise && this.enableDP) {
        predictions = this._addDifferentialPrivacyNoise(predictions, {
          epsilon: this.epsilon / 10,
          sensitivity: 1.0,
          mechanism: this.dpOptions.mechanism
        });
      }

      return predictions;
    } catch (error) {
      logger.error('Prediction failed:', error);
      throw new Error(`Prediction failed: ${error.message}`);
    }
  }

  /**
   * Evaluate the model
   * @param {Array<Array<number>>} data - Validation features
   * @param {Array<number>} labels - Validation labels
   * @returns {Promise<Object>} Evaluation metrics
   */
  async evaluate(data, labels) {
    try {
      if (!this.isTrained) throw new Error('Model must be trained');
      const predictions = await this.predict(data);
      const metrics = {};

      switch (this.type) {
        case RegressionType.LINEAR:
        case RegressionType.RIDGE:
        case RegressionType.LASSO:
        case RegressionType.POLYNOMIAL:
        case RegressionType.QUANTILE:
          metrics.mse = this._calculateMSE(predictions, labels);
          metrics.rmse = Math.sqrt(metrics.mse);
          metrics.mae = this._calculateMAE(predictions, labels);
          metrics.r2 = this._calculateR2(predictions, labels);
          break;
        case RegressionType.LOGISTIC:
          metrics.accuracy = this._calculateAccuracy(predictions, labels);
          metrics.precision = this._calculatePrecision(predictions, labels);
          metrics.recall = this._calculateRecall(predictions, labels);
          metrics.f1 = this._calculateF1(metrics.precision, metrics.recall);
          break;
      }

      return metrics;
    } catch (error) {
      logger.error('Evaluation failed:', error);
      throw new Error(`Evaluation failed: ${error.message}`);
    }
  }

  /**
   * Export the model in a serializable format
   * @returns {Object} Serialized model
   */
  export() {
    return {
      type: this.type,
      coefficients: this.coefficients,
      intercept: this.intercept,
      metrics: this.metrics,
      isTrained: this.isTrained,
      createdAt: Date.now()
    };
  }

  /**
   * Import a serialized model
   * @param {Object} serializedModel - Serialized model
   * @returns {boolean} Whether the import was successful
   */
  import(serializedModel) {
    try {
      if (!serializedModel || !serializedModel.type || !serializedModel.coefficients) {
        throw new Error('Invalid serialized model');
      }

      this.type = serializedModel.type;
      this.coefficients = serializedModel.coefficients;
      this.intercept = serializedModel.intercept;
      this.metrics = serializedModel.metrics || this.metrics;
      this.isTrained = serializedModel.isTrained || false;
      this.isInitialized = true;

      logger.info(`Model imported successfully (${this.type}, ${this.coefficients.length} features)`);
      return true;
    } catch (error) {
      logger.error('Model import failed:', error);
      return false;
    }
  }

  /** Private Methods **/

  async _trainLinearRegression(data, labels, weights, privacyParams) {
    if (data.length < 1000 && this.iterativeMethod !== 'force_gradient_descent') {
      logger.info('Using privacy-preserving normal equations');
      let xtx = this._initializeMatrix(data[0].length, data[0].length);
      let xty = Array(data[0].length).fill(0);

      for (let i = 0; i < data.length; i++) {
        const x = this._clipVector(data[i], privacyParams.clippingThreshold);
        const y = labels[i];
        const w = weights ? weights[i] : 1;

        for (let j = 0; j < x.length; j++) {
          for (let k = 0; k < x.length; k++) {
            xtx[j][k] += w * x[j] * x[k];
          }
          xty[j] += w * x[j] * y;
        }
      }

      if (this.enableDP) {
        xtx = this._addNoiseToMatrix(xtx, privacyParams);
        xty = this._addNoiseToVector(xty, privacyParams);
      }

      this.coefficients = this._solveLinearSystem(xtx, xty);
      this.intercept = this._calculateIntercept(data, labels, this.coefficients);
      this.metrics.privacyBudgetUsed = privacyParams.epsilon;
      this.metrics.error = this._calculateMSE(this._predictLinearModel(data), labels);
      this.metrics.iterations = 1;
    } else {
      await this._trainWithGradientDescent(data, labels, weights, privacyParams, this._linearRegressionGradient.bind(this));
    }
  }

  async _trainLogisticRegression(data, labels, weights, privacyParams) {
    await this._trainWithGradientDescent(data, labels, weights, privacyParams, this._logisticRegressionGradient.bind(this));
  }

  async _trainRidgeRegression(data, labels, weights, privacyParams) {
    const lambda = this.iterationOptions.lambda || 0.1;
    await this._trainWithGradientDescent(data, labels, weights, privacyParams, (x, y, w, coef, intcpt) =>
      this._ridgeRegressionGradient(x, y, w, coef, intcpt, lambda)
    );
  }

  async _trainLassoRegression(data, labels, weights, privacyParams) {
    const lambda = this.iterationOptions.lambda || 0.1;
    await this._trainWithProximalGradientDescent(data, labels, weights, privacyParams, this._linearRegressionGradient.bind(this), lambda);
  }

  async _trainPolynomialRegression(data, labels, weights, privacyParams) {
    const degree = this.iterationOptions.degree || 2;
    const polyData = this._generatePolynomialFeatures(data, degree);
    await this._trainLinearRegression(polyData, labels, weights, privacyParams);
  }

  async _trainQuantileRegression(data, labels, weights, privacyParams) {
    const tau = this.iterationOptions.quantile || 0.5;
    await this._trainWithGradientDescent(data, labels, weights, privacyParams, (x, y, w, coef, intcpt) =>
      this._quantileRegressionGradient(x, y, w, coef, intcpt, tau)
    );
  }

  async _trainWithGradientDescent(data, labels, weights, privacyParams, gradientFn) {
    const maxIterations = this.iterationOptions.maxIterations;
    let learningRate = this.iterationOptions.learningRate;
    const convergenceThreshold = this.iterationOptions.convergenceThreshold;
    const batchSize = this.iterationOptions.batchSize || data.length;

    let iteration = 0;
    let previousError = Infinity;
    let privacyBudgetUsed = 0;
    const iterationBudget = privacyParams.epsilon / maxIterations;

    while (iteration < maxIterations) {
      const batchIndices = this._sampleBatchIndices(data.length, batchSize);
      const { coefficientGradients, interceptGradient } = gradientFn(
        batchIndices.map(i => data[i]),
        batchIndices.map(i => labels[i]),
        weights ? batchIndices.map(i => weights[i]) : null,
        this.coefficients,
        this.intercept
      );

      let noisyCoefGradients = coefficientGradients;
      let noisyInterceptGradient = interceptGradient;
      if (this.enableDP) {
        const batchEpsilon = iterationBudget * (batchSize / data.length);
        noisyCoefGradients = this._addNoiseToVector(coefficientGradients, { ...privacyParams, epsilon: batchEpsilon });
        noisyInterceptGradient = this._addNoise(interceptGradient, { ...privacyParams, epsilon: batchEpsilon });
        privacyBudgetUsed += batchEpsilon;
      }

      noisyCoefGradients = this._clipVector(noisyCoefGradients, 10.0);
      noisyInterceptGradient = Math.min(Math.max(noisyInterceptGradient, -10.0), 10.0);

      if (this.secureLearningRate) {
        learningRate = this._secureAdaptiveLearningRate(learningRate, iteration);
      }

      for (let j = 0; j < this.coefficients.length; j++) {
        this.coefficients[j] -= learningRate * noisyCoefGradients[j];
      }
      this.intercept -= learningRate * noisyInterceptGradient;

      const predictions = this._predictLinearModel(data);
      const error = this._calculateMSE(predictions, labels);
      if (Math.abs(previousError - error) < convergenceThreshold) break;
      previousError = error;
      iteration++;
    }

    this.metrics.iterations = iteration;
    this.metrics.error = previousError;
    this.metrics.privacyBudgetUsed = privacyBudgetUsed;
  }

  async _trainWithProximalGradientDescent(data, labels, weights, privacyParams, gradientFn, lambda) {
    const maxIterations = this.iterationOptions.maxIterations;
    let learningRate = this.iterationOptions.learningRate;
    const convergenceThreshold = this.iterationOptions.convergenceThreshold;
    const batchSize = this.iterationOptions.batchSize || data.length;

    let iteration = 0;
    let previousError = Infinity;
    let privacyBudgetUsed = 0;
    const iterationBudget = privacyParams.epsilon / maxIterations;

    while (iteration < maxIterations) {
      const batchIndices = this._sampleBatchIndices(data.length, batchSize);
      const { coefficientGradients, interceptGradient } = gradientFn(
        batchIndices.map(i => data[i]),
        batchIndices.map(i => labels[i]),
        weights ? batchIndices.map(i => weights[i]) : null,
        this.coefficients,
        this.intercept
      );

      let noisyCoefGradients = coefficientGradients;
      let noisyInterceptGradient = interceptGradient;
      if (this.enableDP) {
        const batchEpsilon = iterationBudget * (batchSize / data.length);
        noisyCoefGradients = this._addNoiseToVector(coefficientGradients, { ...privacyParams, epsilon: batchEpsilon });
        noisyInterceptGradient = this._addNoise(interceptGradient, { ...privacyParams, epsilon: batchEpsilon });
        privacyBudgetUsed += batchEpsilon;
      }

      if (this.secureLearningRate) {
        learningRate = this._secureAdaptiveLearningRate(learningRate, iteration);
      }

      for (let j = 0; j < this.coefficients.length; j++) {
        const tempCoef = this.coefficients[j] - learningRate * noisyCoefGradients[j];
        this.coefficients[j] = this._softThreshold(tempCoef, lambda * learningRate);
      }
      this.intercept -= learningRate * noisyInterceptGradient;

      const predictions = this._predictLinearModel(data);
      const error = this._calculateMSE(predictions, labels);
      if (Math.abs(previousError - error) < convergenceThreshold) break;
      previousError = error;
      iteration++;
    }

    this.metrics.iterations = iteration;
    this.metrics.error = previousError;
    this.metrics.privacyBudgetUsed = privacyBudgetUsed;
  }

  _softThreshold(value, threshold) {
    return value > threshold ? value - threshold : (value < -threshold ? value + threshold : 0);
  }

  _linearRegressionGradient(batchData, batchLabels, batchWeights, coefficients, intercept) {
    const coefficientGradients = Array(coefficients.length).fill(0);
    let interceptGradient = 0;

    for (let i = 0; i < batchData.length; i++) {
      const x = batchData[i];
      const y = batchLabels[i];
      const w = batchWeights ? batchWeights[i] : 1;
      let prediction = intercept + x.reduce((sum, val, j) => sum + coefficients[j] * val, 0);
      const error = prediction - y;
      for (let j = 0; j < coefficients.length; j++) {
        coefficientGradients[j] += w * error * x[j];
      }
      interceptGradient += w * error;
    }

    const batchSize = batchData.length;
    return {
      coefficientGradients: coefficientGradients.map(g => g / batchSize),
      interceptGradient: interceptGradient / batchSize
    };
  }

  _logisticRegressionGradient(batchData, batchLabels, batchWeights, coefficients, intercept) {
    const coefficientGradients = Array(coefficients.length).fill(0);
    let interceptGradient = 0;

    for (let i = 0; i < batchData.length; i++) {
      const x = batchData[i];
      const y = batchLabels[i];
      const w = batchWeights ? batchWeights[i] : 1;
      const logit = intercept + x.reduce((sum, val, j) => sum + coefficients[j] * val, 0);
      const sigmoid = 1 / (1 + Math.exp(-logit));
      const error = sigmoid - y;
      for (let j = 0; j < coefficients.length; j++) {
        coefficientGradients[j] += w * error * x[j];
      }
      interceptGradient += w * error;
    }

    const batchSize = batchData.length;
    return {
      coefficientGradients: coefficientGradients.map(g => g / batchSize),
      interceptGradient: interceptGradient / batchSize
    };
  }

  _ridgeRegressionGradient(batchData, batchLabels, batchWeights, coefficients, intercept, lambda) {
    const { coefficientGradients, interceptGradient } = this._linearRegressionGradient(batchData, batchLabels, batchWeights, coefficients, intercept);
    for (let j = 0; j < coefficients.length; j++) {
      coefficientGradients[j] += lambda * coefficients[j];
    }
    return { coefficientGradients, interceptGradient };
  }

  _quantileRegressionGradient(batchData, batchLabels, batchWeights, coefficients, intercept, tau) {
    const coefficientGradients = Array(coefficients.length).fill(0);
    let interceptGradient = 0;

    for (let i = 0; i < batchData.length; i++) {
      const x = batchData[i];
      const y = batchLabels[i];
      const w = batchWeights ? batchWeights[i] : 1;
      const prediction = intercept + x.reduce((sum, val, j) => sum + coefficients[j] * val, 0);
      const error = y - prediction;
      const gradientFactor = error >= 0 ? -tau : -(1 - tau);
      for (let j = 0; j < coefficients.length; j++) {
        coefficientGradients[j] += w * gradientFactor * x[j];
      }
      interceptGradient += w * gradientFactor;
    }

    const batchSize = batchData.length;
    return {
      coefficientGradients: coefficientGradients.map(g => g / batchSize),
      interceptGradient: interceptGradient / batchSize
    };
  }

  _predictLinearModel(data) {
    return data.map(x => this.intercept + x.reduce((sum, val, j) => sum + this.coefficients[j] * val, 0));
  }

  _predictLogisticModel(data) {
    return data.map(x => {
      const logit = this.intercept + x.reduce((sum, val, j) => sum + this.coefficients[j] * val, 0);
      return 1 / (1 + Math.exp(-logit));
    });
  }

  _predictQuantileModel(data) {
    return this._predictLinearModel(data);
  }

  _generatePolynomialFeatures(data, degree) {
    return data.map(x => {
      const expanded = [...x];
      for (let d = 2; d <= degree; d++) {
        for (let j = 0; j < x.length; j++) {
          expanded.push(Math.pow(x[j], d));
        }
      }
      return expanded;
    });
  }

  _calculateIntercept(data, labels, coefficients) {
    let sumError = 0;
    for (let i = 0; i < data.length; i++) {
      const prediction = data[i].reduce((sum, val, j) => sum + coefficients[j] * val, 0);
      sumError += labels[i] - prediction;
    }
    return sumError / data.length;
  }

  _solveLinearSystem(A, b) {
    const n = A.length;
    for (let i = 0; i < n; i++) A[i][i] += 1e-8;
    const L = this._choleskyDecomposition(A);
    const y = Array(n).fill(0);
    for (let i = 0; i < n; i++) {
      let sum = 0;
      for (let j = 0; j < i; j++) sum += L[i][j] * y[j];
      y[i] = (b[i] - sum) / L[i][i];
    }
    const x = Array(n).fill(0);
    for (let i = n - 1; i >= 0; i--) {
      let sum = 0;
      for (let j = i + 1; j < n; j++) sum += L[j][i] * x[j];
      x[i] = (y[i] - sum) / L[i][i];
    }
    return x;
  }

  _choleskyDecomposition(A) {
    const n = A.length;
    const L = Array(n).fill().map(() => Array(n).fill(0));
    for (let i = 0; i < n; i++) {
      for (let j = 0; j <= i; j++) {
        let sum = 0;
        if (j === i) {
          for (let k = 0; k < j; k++) sum += L[j][k] * L[j][k];
          L[j][j] = Math.sqrt(Math.max(A[j][j] - sum, 1e-14));
        } else {
          for (let k = 0; k < j; k++) sum += L[i][k] * L[j][k];
          L[i][j] = (A[i][j] - sum) / L[j][j];
        }
      }
    }
    return L;
  }

  _initializeMatrix(rows, cols) {
    return Array(rows).fill().map(() => Array(cols).fill(0));
  }

  _addNoise(value, privacyParams) {
    if (!this.enableDP) return value;
    const { epsilon, sensitivity, mechanism } = privacyParams;
    switch (mechanism) {
      case 'laplace':
        return value + this._laplacianNoise(sensitivity / epsilon);
      case 'gaussian':
        const sigma = (sensitivity * Math.sqrt(2 * Math.log(1.25 / privacyParams.delta))) / epsilon;
        return value + this._gaussianNoise(sigma);
      default:
        return value + this._laplacianNoise(sensitivity / epsilon);
    }
  }

  _addNoiseToVector(vector, privacyParams) {
    return vector.map(v => this._addNoise(v, privacyParams));
  }

  _addNoiseToMatrix(matrix, privacyParams) {
    return matrix.map(row => this._addNoiseToVector(row, privacyParams));
  }

  _laplacianNoise(scale) {
    const u = Math.random() - 0.5;
    return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  }

  _gaussianNoise(sigma) {
    let u = 0, v = 0;
    while (u === 0) u = Math.random();
    while (v === 0) v = Math.random();
    const z = Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
    return z * sigma;
  }

  _clipVector(vector, threshold) {
    const norm = Math.sqrt(vector.reduce((sum, val) => sum + val * val, 0));
    if (norm > threshold) {
      const scale = threshold / norm;
      return vector.map(v => v * scale);
    }
    return vector;
  }

  _addDifferentialPrivacyNoise(predictions, params) {
    return predictions.map(p => this._addNoise(p, params));
  }

  _generateInitialWeight() {
    return (Math.random() - 0.5) * 0.01;
  }

  _secureAdaptiveLearningRate(initialLR, iteration) {
    return initialLR / (1 + 0.01 * iteration);
  }

  _sampleBatchIndices(dataSize, batchSize) {
    if (batchSize >= dataSize) return Array.from({ length: dataSize }, (_, i) => i);
    const indices = new Set();
    while (indices.size < batchSize) indices.add(Math.floor(Math.random() * dataSize));
    return Array.from(indices);
  }

  _calculateMSE(predictions, actual) {
    return predictions.reduce((sum, p, i) => sum + Math.pow(p - actual[i], 2), 0) / predictions.length;
  }

  _calculateMAE(predictions, actual) {
    return predictions.reduce((sum, p, i) => sum + Math.abs(p - actual[i]), 0) / predictions.length;
  }

  _calculateR2(predictions, actual) {
    const mean = actual.reduce((sum, val) => sum + val, 0) / actual.length;
    const totalSS = actual.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0);
    const residualSS = predictions.reduce((sum, p, i) => sum + Math.pow(p - actual[i], 2), 0);
    return 1 - (residualSS / totalSS);
  }

  _calculateAccuracy(predictions, actual) {
    return predictions.filter((p, i) => (p >= 0.5 ? 1 : 0) === actual[i]).length / predictions.length;
  }

  _calculatePrecision(predictions, actual) {
    let tp = 0, fp = 0;
    predictions.forEach((p, i) => {
      const predClass = p >= 0.5 ? 1 : 0;
      if (predClass === 1 && actual[i] === 1) tp++;
      else if (predClass === 1 && actual[i] === 0) fp++;
    });
    return tp + fp > 0 ? tp / (tp + fp) : 0;
  }

  _calculateRecall(predictions, actual) {
    let tp = 0, fn = 0;
    predictions.forEach((p, i) => {
      const predClass = p >= 0.5 ? 1 : 0;
      if (predClass === 1 && actual[i] === 1) tp++;
      else if (predClass === 0 && actual[i] === 1) fn++;
    });
    return tp + fn > 0 ? tp / (tp + fn) : 0;
  }

  _calculateF1(precision, recall) {
    return precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
  }
}

module.exports = { RegressionModel, RegressionType };
