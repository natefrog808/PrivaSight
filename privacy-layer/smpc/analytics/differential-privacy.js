/**
 * @fileoverview Differential Privacy Utilities for PrivaSight
 * 
 * A comprehensive set of tools for implementing differential privacy in machine learning models.
 * This module provides mechanisms for adding calibrated noise, tracking privacy budgets,
 * and implementing advanced composition theorems. It's designed to work with PrivaSight's
 * federated learning, regression, and clustering modules.
 */

// Common noise mechanisms for differential privacy utilities
const NoiseMechanism = {
  LAPLACE: 'LAPLACE',
  GAUSSIAN: 'GAUSSIAN',
  EXPONENTIAL: 'EXPONENTIAL',
  STAIRCASE: 'STAIRCASE',
  DISCRETE_LAPLACE: 'DISCRETE_LAPLACE',
  DISCRETE_GAUSSIAN: 'DISCRETE_GAUSSIAN',
};

// Methods for privacy budget allocation across operations
const BudgetAllocationMethod = {
  UNIFORM: 'UNIFORM',              // Equal budget for each operation
  SEQUENTIAL: 'SEQUENTIAL',        // Full budget for each operation, stopping when depleted
  ADAPTIVE: 'ADAPTIVE',            // Adjust allocation based on remaining queries
  IMPORTANCE: 'IMPORTANCE',        // Allocate based on importance score
  GEOMETRIC: 'GEOMETRIC',          // Geometrically decreasing budget
  RENYI_ADAPTIVE: 'RENYI_ADAPTIVE' // Adaptive allocation using Rényi DP
};

// Composition theorems for calculating cumulative privacy loss
const CompositionTheorem = {
  BASIC: 'BASIC',               // Basic composition (linear)
  ADVANCED: 'ADVANCED',         // Advanced composition (sublinear)
  ZERO_CONCENTRATED: 'ZERO_CONCENTRATED', // Zero-concentrated DP
  RENYI: 'RENYI',               // Rényi DP composition
  MOMENTS_ACCOUNTANT: 'MOMENTS_ACCOUNTANT', // Moments accountant
  GAUSSIAN_DIFFERENTIAL_PRIVACY: 'GAUSSIAN_DIFFERENTIAL_PRIVACY' // GDP
};

/**
 * Main class for differential privacy mechanisms and utilities.
 */
class DifferentialPrivacy {
  /**
   * Creates a new differential privacy manager.
   * @param {Object} options - Configuration options
   * @param {number} [options.epsilon=1.0] - Privacy parameter (lower = more private)
   * @param {number} [options.delta=1e-6] - Failure probability (for (ε,δ)-DP)
   * @param {number} [options.sensitivity=1.0] - Sensitivity of the function
   * @param {NoiseMechanism} [options.noiseMechanism=NoiseMechanism.GAUSSIAN] - Type of noise to add
   * @param {CompositionTheorem} [options.compositionTheorem=CompositionTheorem.ADVANCED] - Method for tracking privacy loss
   * @param {BudgetAllocationMethod} [options.budgetAllocationMethod=BudgetAllocationMethod.UNIFORM] - How to allocate privacy budget
   * @param {number} [options.maxBudget=options.epsilon] - Maximum privacy budget to use
   * @param {boolean} [options.autoReset=false] - Whether to reset budget on depletion
   */
  constructor(options = {}) {
    // Core privacy parameters
    this.epsilon = options.epsilon || 1.0;
    this.delta = options.delta || 1e-6;
    this.sensitivity = options.sensitivity || 1.0;

    // Noise and composition configuration
    this.noiseMechanism = options.noiseMechanism || NoiseMechanism.GAUSSIAN;
    this.compositionTheorem = options.compositionTheorem || CompositionTheorem.ADVANCED;
    this.budgetAllocationMethod = options.budgetAllocationMethod || BudgetAllocationMethod.UNIFORM;

    // Budget management
    this.maxBudget = options.maxBudget || this.epsilon;
    this.remainingBudget = this.maxBudget;
    this.autoReset = options.autoReset || false;

    // Tracking and accounting
    this.queryHistory = [];
    this.currentNoiseScale = this._calculateNoiseScale();
    this.momentsAccountant = { lambda: 32, moments: [] };

    // Initialize noise mechanisms
    this._setupNoiseMechanisms();
  }

  // **Public Methods**

  /**
   * Adds Laplace noise to a numeric value.
   * @param {number} value - Numeric value to privatize
   * @param {number} [sensitivity=this.sensitivity] - Sensitivity of the value
   * @param {number} [customEpsilon] - Optional custom epsilon for this operation
   * @returns {number} Value with added noise
   */
  addLaplaceNoise(value, sensitivity = this.sensitivity, customEpsilon = null) {
    const epsilon = this._allocatePrivacyBudget(customEpsilon || this.epsilon);
    const scale = sensitivity / epsilon;
    const noise = this._generateLaplaceNoise(scale);
    this._recordQuery('laplace', { value, sensitivity, epsilon, scale, noise });
    return value + noise;
  }

  /**
   * Adds Gaussian noise to a numeric value.
   * @param {number} value - Numeric value to privatize
   * @param {number} [sensitivity=this.sensitivity] - Sensitivity of the value
   * @param {number} [customEpsilon] - Optional custom epsilon for this operation
   * @param {number} [customDelta] - Optional custom delta for this operation
   * @returns {number} Value with added noise
   */
  addGaussianNoise(value, sensitivity = this.sensitivity, customEpsilon = null, customDelta = null) {
    const epsilon = this._allocatePrivacyBudget(customEpsilon || this.epsilon);
    const delta = customDelta || this.delta;
    const scale = this._calibrateGaussianScale(sensitivity, epsilon, delta);
    const noise = this._generateGaussianNoise(0, scale);
    this._recordQuery('gaussian', { value, sensitivity, epsilon, delta, scale, noise });
    return value + noise;
  }

  /**
   * Adds differential privacy to an array of numeric values.
   * @param {Array<number>} values - Array of numeric values
   * @param {number} [sensitivity=this.sensitivity] - L1 or L2 sensitivity of the values
   * @param {boolean} [isL1Sensitivity=true] - Whether sensitivity is L1 (true) or L2 (false)
   * @param {NoiseMechanism} [mechanism] - Noise mechanism to use
   * @returns {Array<number>} Values with added noise
   */
  privatizeArray(values, sensitivity = this.sensitivity, isL1Sensitivity = true, mechanism = null) {
    const useMechanism = mechanism || (isL1Sensitivity ? NoiseMechanism.LAPLACE : NoiseMechanism.GAUSSIAN);
    const epsilon = this._allocatePrivacyBudget(this.epsilon);
    const result = values.map(value => {
      switch (useMechanism) {
        case NoiseMechanism.LAPLACE:
          return this._privatizeValueWithLaplace(value, sensitivity, epsilon);
        case NoiseMechanism.GAUSSIAN:
          return this._privatizeValueWithGaussian(value, sensitivity, epsilon, this.delta);
        case NoiseMechanism.EXPONENTIAL:
          return this._privatizeValueWithExponential(value, sensitivity, epsilon);
        case NoiseMechanism.DISCRETE_LAPLACE:
          return this._privatizeValueWithDiscreteLaplace(value, sensitivity, epsilon);
        case NoiseMechanism.DISCRETE_GAUSSIAN:
          return this._privatizeValueWithDiscreteGaussian(value, sensitivity, epsilon, this.delta);
        case NoiseMechanism.STAIRCASE:
          return this._privatizeValueWithStaircase(value, sensitivity, epsilon);
        default:
          return this._privatizeValueWithLaplace(value, sensitivity, epsilon);
      }
    });
    this._recordQuery('array', { count: values.length, sensitivity, isL1Sensitivity, mechanism: useMechanism, epsilon });
    return result;
  }

  /**
   * Performs differentially private quantile estimation.
   * @param {Array<number>} data - Data array to compute quantile from
   * @param {number} quantile - Quantile to compute (0-1)
   * @param {number} [epsilon] - Privacy parameter
   * @returns {number} Differentially private quantile estimate
   */
  privatizeQuantile(data, quantile, epsilon = null) {
    const eps = this._allocatePrivacyBudget(epsilon || this.epsilon);
    const sortedData = [...data].sort((a, b) => a - b);
    const range = sortedData[sortedData.length - 1] - sortedData[0];
    const trueIndex = Math.floor(quantile * (sortedData.length - 1));
    const trueQuantile = sortedData[trueIndex];
    const sensitivity = range;
    const noisyQuantile = this._privatizeValueWithLaplace(trueQuantile, sensitivity, eps);
    this._recordQuery('quantile', { dataSize: data.length, quantile, epsilon: eps, sensitivity });
    return noisyQuantile;
  }

  /**
   * Implements the exponential mechanism for categorical data.
   * @param {Array<Object>} candidates - Array of candidate objects
   * @param {Function} utilityFn - Function that maps candidates to utility scores
   * @param {number} [sensitivity=1.0] - Sensitivity of the utility function
   * @param {number} [epsilon] - Privacy parameter
   * @returns {Object} Selected candidate
   */
  exponentialMechanism(candidates, utilityFn, sensitivity = 1.0, epsilon = null) {
    const eps = this._allocatePrivacyBudget(epsilon || this.epsilon);
    const utilities = candidates.map(utilityFn);
    const weights = utilities.map(u => Math.exp(eps * u / (2 * sensitivity)));
    const totalWeight = weights.reduce((sum, w) => sum + w, 0);
    const probabilities = weights.map(w => w / totalWeight);
    const r = Math.random();
    let cumulativeProbability = 0;
    let selectedIndex = 0;
    for (let i = 0; i < probabilities.length; i++) {
      cumulativeProbability += probabilities[i];
      if (r <= cumulativeProbability) {
        selectedIndex = i;
        break;
      }
    }
    this._recordQuery('exponential', { candidateCount: candidates.length, epsilon: eps, sensitivity });
    return candidates[selectedIndex];
  }

  /**
   * Implements differentially private histogram.
   * @param {Array<any>} data - Original data points
   * @param {Function} binningFn - Function to bin data points
   * @param {number} [epsilon] - Privacy parameter
   * @returns {Object} Differentially private histogram
   */
  privatizeHistogram(data, binningFn, epsilon = null) {
    const eps = this._allocatePrivacyBudget(epsilon || this.epsilon);
    const histogram = {};
    for (const item of data) {
      const bin = binningFn(item);
      histogram[bin] = (histogram[bin] || 0) + 1;
    }
    const sensitivity = 1;
    const noisyHistogram = {};
    for (const bin in histogram) {
      const noisyCount = this._privatizeValueWithLaplace(histogram[bin], sensitivity, eps);
      noisyHistogram[bin] = Math.max(0, Math.round(noisyCount));
    }
    this._recordQuery('histogram', { dataSize: data.length, binCount: Object.keys(histogram).length, epsilon: eps, sensitivity });
    return noisyHistogram;
  }

  /**
   * Implements differentially private count.
   * @param {number} count - True count to privatize
   * @param {number} [epsilon] - Privacy parameter
   * @returns {number} Privatized count
   */
  privatizeCount(count, epsilon = null) {
    const eps = this._allocatePrivacyBudget(epsilon || this.epsilon);
    const sensitivity = 1;
    const noisyCount = this._privatizeValueWithLaplace(count, sensitivity, eps);
    const result = Math.max(0, Math.round(noisyCount));
    this._recordQuery('count', { trueCount: count, epsilon: eps, sensitivity });
    return result;
  }

  /**
   * Implements differentially private mean estimation.
   * @param {Array<number>} data - Data to compute mean for
   * @param {number} lowerBound - Lower bound of data range
   * @param {number} upperBound - Upper bound of data range
   * @param {number} [epsilon] - Privacy parameter
   * @returns {number} Privatized mean
   */
  privatizeMean(data, lowerBound, upperBound, epsilon = null) {
    const eps = this._allocatePrivacyBudget(epsilon || this.epsilon);
    const clampedData = data.map(x => Math.max(lowerBound, Math.min(upperBound, x)));
    const trueMean = clampedData.reduce((sum, x) => sum + x, 0) / clampedData.length;
    const sensitivity = (upperBound - lowerBound) / data.length;
    const noisyMean = this._privatizeValueWithLaplace(trueMean, sensitivity, eps);
    this._recordQuery('mean', { dataSize: data.length, epsilon: eps, sensitivity, bounds: [lowerBound, upperBound] });
    return noisyMean;
  }

  /**
   * Implements differentially private sum.
   * @param {Array<number>} data - Data to compute sum for
   * @param {number} lowerBound - Lower bound of data range
   * @param {number} upperBound - Upper bound of data range
   * @param {number} [epsilon] - Privacy parameter
   * @returns {number} Privatized sum
   */
  privatizeSum(data, lowerBound, upperBound, epsilon = null) {
    const eps = this._allocatePrivacyBudget(epsilon || this.epsilon);
    const clampedData = data.map(x => Math.max(lowerBound, Math.min(upperBound, x)));
    const trueSum = clampedData.reduce((sum, x) => sum + x, 0);
    const sensitivity = upperBound - lowerBound;
    const noisySum = this._privatizeValueWithLaplace(trueSum, sensitivity, eps);
    this._recordQuery('sum', { dataSize: data.length, epsilon: eps, sensitivity, bounds: [lowerBound, upperBound] });
    return noisySum;
  }

  /**
   * Implements differentially private variance estimation.
   * @param {Array<number>} data - Data to compute variance for
   * @param {number} lowerBound - Lower bound of data range
   * @param {number} upperBound - Upper bound of data range
   * @param {number} [epsilon] - Privacy parameter
   * @returns {number} Privatized variance
   */
  privatizeVariance(data, lowerBound, upperBound, epsilon = null) {
    if (data.length <= 1) return 0;
    const eps = this._allocatePrivacyBudget(epsilon || this.epsilon);
    const epsMean = eps / 2;
    const epsVar = eps / 2;
    const privateMean = this.privatizeMean(data, lowerBound, upperBound, epsMean);
    const squaredDist = data.map(x => Math.pow(Math.max(lowerBound, Math.min(upperBound, x)) - privateMean, 2));
    const trueVariance = squaredDist.reduce((sum, x) => sum + x, 0) / (data.length - 1);
    const sensitivity = Math.pow(upperBound - lowerBound, 2) / (data.length - 1);
    const noisyVariance = this._privatizeValueWithLaplace(trueVariance, sensitivity, epsVar);
    const result = Math.max(0, noisyVariance);
    this._recordQuery('variance', { dataSize: data.length, epsilon: eps, sensitivity, bounds: [lowerBound, upperBound] });
    return result;
  }

  /**
   * Implements sparse vector technique for answering threshold queries.
   * @param {Array<Function>} queries - Array of query functions
   * @param {number} threshold - Threshold value
   * @param {number} maxResponses - Maximum number of above-threshold responses
   * @param {number} [epsilon] - Privacy parameter
   * @returns {Array<boolean>} Array indicating which queries are above threshold
   */
  sparseVector(queries, threshold, maxResponses, epsilon = null) {
    const eps = this._allocatePrivacyBudget(epsilon || this.epsilon);
    const eps1 = eps / 2;
    const eps2 = eps / 2;
    const noisyThreshold = threshold + this._generateLaplaceNoise(1 / eps1);
    const results = new Array(queries.length).fill(false);
    let responsesLeft = maxResponses;
    for (let i = 0; i < queries.length && responsesLeft > 0; i++) {
      const queryValue = queries[i]();
      const noisyValue = queryValue + this._generateLaplaceNoise(2 * maxResponses / eps2);
      if (noisyValue >= noisyThreshold) {
        results[i] = true;
        responsesLeft--;
      }
    }
    this._recordQuery('sparseVector', { queryCount: queries.length, threshold, maxResponses, epsilon: eps });
    return results;
  }

  /**
   * Checks if there is sufficient privacy budget remaining for an operation.
   * @param {number} requiredBudget - Budget required for the operation
   * @returns {boolean} Whether sufficient budget is available
   */
  hasSufficientBudget(requiredBudget) {
    switch (this.compositionTheorem) {
      case CompositionTheorem.BASIC:
        return this.remainingBudget >= requiredBudget;
      case CompositionTheorem.ADVANCED:
        const effectiveBudget = this._getEffectiveBudgetCost(requiredBudget);
        return this.remainingBudget >= effectiveBudget;
      case CompositionTheorem.ZERO_CONCENTRATED:
      case CompositionTheorem.RENYI:
      case CompositionTheorem.MOMENTS_ACCOUNTANT:
      case CompositionTheorem.GAUSSIAN_DIFFERENTIAL_PRIVACY:
        return this._checkBudgetForAdvancedComposition(requiredBudget);
      default:
        return this.remainingBudget >= requiredBudget;
    }
  }

  /**
   * Resets the privacy budget to its initial state.
   */
  resetPrivacyBudget() {
    this.remainingBudget = this.maxBudget;
    this.queryHistory = [];
    this.momentsAccountant.moments = [];
  }

  /**
   * Gets current statistics about privacy budget usage.
   * @returns {Object} Budget usage statistics
   */
  getBudgetStatistics() {
    return {
      initialBudget: this.maxBudget,
      remainingBudget: this.remainingBudget,
      epsilon: this.epsilon,
      delta: this.delta,
      queriesExecuted: this.queryHistory.length,
      compositionTheorem: this.compositionTheorem,
      budgetAllocationMethod: this.budgetAllocationMethod,
      queryTypes: this._countQueryTypeFrequency(),
      timestamp: Date.now(),
    };
  }

  /**
   * Sets the noise mechanism to use for adding noise.
   * @param {NoiseMechanism} mechanism - Noise mechanism to use
   */
  setNoiseMechanism(mechanism) {
    if (!Object.values(NoiseMechanism).includes(mechanism)) throw new Error(`Unknown noise mechanism: ${mechanism}`);
    this.noiseMechanism = mechanism;
    this.currentNoiseScale = this._calculateNoiseScale();
  }

  /**
   * Sets the composition theorem for tracking privacy budget.
   * @param {CompositionTheorem} theorem - Composition theorem to use
   */
  setCompositionTheorem(theorem) {
    if (!Object.values(CompositionTheorem).includes(theorem)) throw new Error(`Unknown composition theorem: ${theorem}`);
    this.compositionTheorem = theorem;
  }

  /**
   * Sets the budget allocation method.
   * @param {BudgetAllocationMethod} method - Budget allocation method to use
   */
  setBudgetAllocationMethod(method) {
    if (!Object.values(BudgetAllocationMethod).includes(method)) throw new Error(`Unknown budget allocation method: ${method}`);
    this.budgetAllocationMethod = method;
  }

  // **Private Methods**

  _calculateNoiseScale() {
    switch (this.noiseMechanism) {
      case NoiseMechanism.LAPLACE: return this.sensitivity / this.epsilon;
      case NoiseMechanism.GAUSSIAN: return this._calibrateGaussianScale(this.sensitivity, this.epsilon, this.delta);
      case NoiseMechanism.EXPONENTIAL: return 2 * this.sensitivity / this.epsilon;
      case NoiseMechanism.STAIRCASE: return this.sensitivity / this.epsilon;
      case NoiseMechanism.DISCRETE_LAPLACE: return Math.ceil(this.sensitivity / this.epsilon);
      case NoiseMechanism.DISCRETE_GAUSSIAN: return Math.sqrt(2 * Math.log(1.25 / this.delta)) * this.sensitivity / this.epsilon;
      default: return this.sensitivity / this.epsilon;
    }
  }

  _setupNoiseMechanisms() {
    this.noiseScales = {
      [NoiseMechanism.LAPLACE]: this._calculateNoiseScale(),
      [NoiseMechanism.GAUSSIAN]: this._calibrateGaussianScale(this.sensitivity, this.epsilon, this.delta),
      [NoiseMechanism.EXPONENTIAL]: 2 * this.sensitivity / this.epsilon,
      [NoiseMechanism.STAIRCASE]: this.sensitivity / this.epsilon,
      [NoiseMechanism.DISCRETE_LAPLACE]: Math.ceil(this.sensitivity / this.epsilon),
      [NoiseMechanism.DISCRETE_GAUSSIAN]: Math.sqrt(2 * Math.log(1.25 / this.delta)) * this.sensitivity / this.epsilon,
    };
  }

  _generateLaplaceNoise(scale) {
    const u = Math.random() - 0.5;
    return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  }

  _generateGaussianNoise(mean, stdDev) {
    const u1 = Math.random(), u2 = Math.random();
    const z0 = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
    return mean + stdDev * z0;
  }

  _calibrateGaussianScale(sensitivity, epsilon, delta) {
    const c = Math.sqrt(2 * Math.log(1.25 / delta));
    return c * sensitivity / epsilon;
  }

  _generateDiscreteLaplaceNoise(scale) {
    const p = 1 - Math.exp(-1 / scale);
    const u = Math.random();
    if (u < 0.5) return Math.floor(Math.log(2 * u) / Math.log(1 - p));
    return -Math.floor(Math.log(2 * (1 - u)) / Math.log(1 - p));
  }

  _generateDiscreteGaussianNoise(sigma) {
    return Math.round(this._generateGaussianNoise(0, sigma));
  }

  _generateStaircaseNoise(scale) {
    const u = Math.random();
    const sign = Math.random() < 0.5 ? -1 : 1;
    const p = Math.exp(-1 / scale);
    let cdf = 0, k = 0;
    while (true) {
      const probMass = (1 - p) * Math.pow(p, k);
      cdf += probMass;
      if (u <= cdf) return sign * (k + (Math.random() < 0.5 ? 0 : 1));
      k++;
    }
  }

  _privatizeValueWithLaplace(value, sensitivity, epsilon) {
    const scale = sensitivity / epsilon;
    return value + this._generateLaplaceNoise(scale);
  }

  _privatizeValueWithGaussian(value, sensitivity, epsilon, delta) {
    const sigma = this._calibrateGaussianScale(sensitivity, epsilon, delta);
    return value + this._generateGaussianNoise(0, sigma);
  }

  _privatizeValueWithExponential(value, sensitivity, epsilon) {
    const scale = 2 * sensitivity / epsilon;
    const delta = this._generateLaplaceNoise(scale);
    return value + delta;
  }

  _privatizeValueWithDiscreteLaplace(value, sensitivity, epsilon) {
    const scale = Math.ceil(sensitivity / epsilon);
    const noise = this._generateDiscreteLaplaceNoise(scale);
    return Math.round(value) + noise;
  }

  _privatizeValueWithDiscreteGaussian(value, sensitivity, epsilon, delta) {
    const sigma = this._calibrateGaussianScale(sensitivity, epsilon, delta);
    const noise = this._generateDiscreteGaussianNoise(sigma);
    return Math.round(value) + noise;
  }

  _privatizeValueWithStaircase(value, sensitivity, epsilon) {
    const scale = sensitivity / epsilon;
    const noise = this._generateStaircaseNoise(scale);
    return value + noise;
  }

  _allocatePrivacyBudget(requestedBudget) {
    if (this.remainingBudget <= 0) {
      if (this.autoReset) this.resetPrivacyBudget();
      else throw new Error('Privacy budget exhausted');
    }
    let allocatedBudget;
    switch (this.budgetAllocationMethod) {
      case BudgetAllocationMethod.UNIFORM:
        allocatedBudget = Math.min(requestedBudget, this.maxBudget / 100);
        break;
      case BudgetAllocationMethod.SEQUENTIAL:
        allocatedBudget = Math.min(requestedBudget, this.remainingBudget);
        break;
      case BudgetAllocationMethod.ADAPTIVE:
        const estimatedRemainingQueries = 100 - this.queryHistory.length;
        const adaptiveBudget = this.remainingBudget / Math.max(1, estimatedRemainingQueries);
        allocatedBudget = Math.min(requestedBudget, adaptiveBudget);
        break;
      case BudgetAllocationMethod.IMPORTANCE:
        allocatedBudget = Math.min(requestedBudget, this.remainingBudget * (requestedBudget / this.epsilon));
        break;
      case BudgetAllocationMethod.GEOMETRIC:
        const decayFactor = 0.95;
        const queryIndex = this.queryHistory.length;
        const geometricBudget = this.maxBudget * Math.pow(decayFactor, queryIndex);
        allocatedBudget = Math.min(requestedBudget, geometricBudget);
        break;
      case BudgetAllocationMethod.RENYI_ADAPTIVE:
        allocatedBudget = this._allocateRenyiAdaptiveBudget(requestedBudget);
        break;
      default:
        allocatedBudget = Math.min(requestedBudget, this.remainingBudget);
    }
    this._updateRemainingBudget(allocatedBudget);
    return allocatedBudget;
  }

  _updateRemainingBudget(usedBudget) {
    switch (this.compositionTheorem) {
      case CompositionTheorem.BASIC:
        this.remainingBudget -= usedBudget;
        break;
      case CompositionTheorem.ADVANCED:
        const effectiveBudgetCost = this._getEffectiveBudgetCost(usedBudget);
        this.remainingBudget -= effectiveBudgetCost;
        break;
      case CompositionTheorem.ZERO_CONCENTRATED:
      case CompositionTheorem.RENYI:
      case CompositionTheorem.MOMENTS_ACCOUNTANT:
      case CompositionTheorem.GAUSSIAN_DIFFERENTIAL_PRIVACY:
        this._updateAdvancedCompositionBudget(usedBudget);
        break;
      default:
        this.remainingBudget -= usedBudget;
    }
    this.remainingBudget = Math.max(0, this.remainingBudget);
  }

  _getEffectiveBudgetCost(epsilon) {
    const k = this.queryHistory.length + 1;
    const delta = this.delta;
    const factor = Math.sqrt(2 * k * Math.log(1 / delta));
    const totalCostBefore = (k > 1) ? epsilon * Math.sqrt(2 * (k - 1) * Math.log(1 / delta)) : 0;
    const totalCostAfter = epsilon * factor;
    return totalCostAfter - totalCostBefore;
  }

  _updateAdvancedCompositionBudget(epsilon) {
    switch (this.compositionTheorem) {
      case CompositionTheorem.ZERO_CONCENTRATED:
        const rho = epsilon * epsilon / 2;
        this._updateZCDPBudget(rho);
        break;
      case CompositionTheorem.RENYI:
        this._updateRenyiDPBudget(epsilon);
        break;
      case CompositionTheorem.MOMENTS_ACCOUNTANT:
        this._updateMomentsAccountant(epsilon);
        break;
      case CompositionTheorem.GAUSSIAN_DIFFERENTIAL_PRIVACY:
        this._updateGDPBudget(epsilon);
        break;
    }
    this.remainingBudget = this._calculateApproximateRemainingBudget();
  }

  _updateZCDPBudget(rho) {
    this.zcdpRho = (this.zcdpRho || 0) + rho;
  }

  _updateRenyiDPBudget(epsilon) {
    if (!this.renyiDivergence) this.renyiDivergence = { 2: 0, 4: 0, 8: 0, 16: 0, 32: 0, 64: 0 };
    const sigma = this._calibrateGaussianScale(1, epsilon, this.delta);
    for (const alpha in this.renyiDivergence) {
      const alphaN = Number(alpha);
      this.renyiDivergence[alpha] += alphaN / (2 * sigma * sigma);
    }
  }

  _updateMomentsAccountant(epsilon) {
    const sigma = this._calibrateGaussianScale(1, epsilon, this.delta);
    const lambda = this.momentsAccountant.lambda;
    const moment = lambda * (lambda + 1) / (2 * sigma * sigma);
    this.momentsAccountant.moments[lambda] = (this.momentsAccountant.moments[lambda] || 0) + moment;
  }

  _updateGDPBudget(epsilon) {
    const delta = this.delta;
    const mu = epsilon / Math.sqrt(2 * Math.log(1.25 / delta));
    this.gdpMu = (this.gdpMu || 0) + mu;
  }

  _calculateApproximateRemainingBudget() {
    switch (this.compositionTheorem) {
      case CompositionTheorem.ZERO_CONCENTRATED:
        if (!this.zcdpRho) return this.maxBudget;
        const epsilonUsed = Math.sqrt(2 * this.zcdpRho * Math.log(1 / this.delta)) + 2 * this.zcdpRho * Math.sqrt(Math.log(1 / this.delta));
        return Math.max(0, this.maxBudget - epsilonUsed);
      case CompositionTheorem.RENYI:
        if (!this.renyiDivergence) return this.maxBudget;
        let minEpsilon = Infinity;
        for (const alpha in this.renyiDivergence) {
          const alphaN = Number(alpha);
          const divergence = this.renyiDivergence[alpha];
          const eps = divergence + Math.log(1 / this.delta) / (alphaN - 1);
          minEpsilon = Math.min(minEpsilon, eps);
        }
        return Math.max(0, this.maxBudget - minEpsilon);
      case CompositionTheorem.MOMENTS_ACCOUNTANT:
        if (!this.momentsAccountant.moments[this.momentsAccountant.lambda]) return this.maxBudget;
        const moment = this.momentsAccountant.moments[this.momentsAccountant.lambda];
        const lambda = this.momentsAccountant.lambda;
        const epsilonUsed = (moment + Math.log(1 / this.delta)) / lambda;
        return Math.max(0, this.maxBudget - epsilonUsed);
      case CompositionTheorem.GAUSSIAN_DIFFERENTIAL_PRIVACY:
        if (!this.gdpMu) return this.maxBudget;
        const epsilonUsed = this.gdpMu * Math.sqrt(2 * Math.log(1.25 / this.delta));
        return Math.max(0, this.maxBudget - epsilonUsed);
      default:
        return this.remainingBudget;
    }
  }

  _checkBudgetForAdvancedComposition(requiredBudget) {
    switch (this.compositionTheorem) {
      case CompositionTheorem.ZERO_CONCENTRATED:
        const maxRho = this.maxBudget * this.maxBudget / 2;
        return (this.zcdpRho || 0) + (requiredBudget * requiredBudget / 2) <= maxRho;
      case CompositionTheorem.RENYI:
        for (const alpha in this.renyiDivergence) {
          const alphaN = Number(alpha);
          const currentDiv = this.renyiDivergence[alpha];
          const maxDiv = (this.maxBudget - Math.log(1 / this.delta) / (alphaN - 1)) * alphaN;
          const sigma = this._calibrateGaussianScale(1, requiredBudget, this.delta);
          const addedDiv = alphaN / (2 * sigma * sigma);
          if (currentDiv + addedDiv > maxDiv) return false;
        }
        return true;
      case CompositionTheorem.MOMENTS_ACCOUNTANT:
        const lambda = this.momentsAccountant.lambda;
        const currentMoment = this.momentsAccountant.moments[lambda] || 0;
        const maxMoment = lambda * this.maxBudget - Math.log(1 / this.delta);
        const sigma = this._calibrateGaussianScale(1, requiredBudget, this.delta);
        const addedMoment = lambda * (lambda + 1) / (2 * sigma * sigma);
        return currentMoment + addedMoment <= maxMoment;
      case CompositionTheorem.GAUSSIAN_DIFFERENTIAL_PRIVACY:
        const maxMu = this.maxBudget / Math.sqrt(2 * Math.log(1.25 / this.delta));
        const mu = requiredBudget / Math.sqrt(2 * Math.log(1.25 / this.delta));
        return (this.gdpMu || 0) + mu <= maxMu;
      default:
        return this.remainingBudget >= requiredBudget;
    }
  }

  _allocateRenyiAdaptiveBudget(requestedBudget) {
    if (this.queryHistory.length === 0) return Math.min(requestedBudget, this.remainingBudget * 0.2);
    const estimatedTotalQueries = 100;
    const remainingQueries = estimatedTotalQueries - this.queryHistory.length;
    const decayFactor = 0.95;
    const queryIndex = this.queryHistory.length;
    const allocation = this.remainingBudget * (1 - decayFactor) * Math.pow(decayFactor, queryIndex);
    return Math.min(requestedBudget, allocation);
  }

  _recordQuery(queryType, metadata) {
    this.queryHistory.push({ type: queryType, timestamp: Date.now(), metadata, remainingBudget: this.remainingBudget });
  }

  _countQueryTypeFrequency() {
    const counts = {};
    for (const query of this.queryHistory) counts[query.type] = (counts[query.type] || 0) + 1;
    return counts;
  }
}

/**
 * Factory methods for creating commonly used DP configurations.
 */
class DPFactory {
  static highPrivacy(options = {}) {
    return new DifferentialPrivacy({
      epsilon: 0.1,
      delta: 1e-7,
      noiseMechanism: NoiseMechanism.GAUSSIAN,
      compositionTheorem: CompositionTheorem.RENYI,
      ...options
    });
  }

  static moderatePrivacy(options = {}) {
    return new DifferentialPrivacy({
      epsilon: 1.0,
      delta: 1e-6,
      noiseMechanism: NoiseMechanism.GAUSSIAN,
      compositionTheorem: CompositionTheorem.ADVANCED,
      ...options
    });
  }

  static lowPrivacy(options = {}) {
    return new DifferentialPrivacy({
      epsilon: 10.0,
      delta: 1e-5,
      noiseMechanism: NoiseMechanism.LAPLACE,
      compositionTheorem: CompositionTheorem.BASIC,
      ...options
    });
  }

  static forNumericalData(options = {}) {
    return new DifferentialPrivacy({
      epsilon: 1.0,
      noiseMechanism: NoiseMechanism.LAPLACE,
      compositionTheorem: CompositionTheorem.ADVANCED,
      ...options
    });
  }

  static forCategoricalData(options = {}) {
    return new DifferentialPrivacy({
      epsilon: 0.5,
      noiseMechanism: NoiseMechanism.EXPONENTIAL,
      compositionTheorem: CompositionTheorem.ADVANCED,
      ...options
    });
  }

  static forTimeSeriesData(options = {}) {
    return new DifferentialPrivacy({
      epsilon: 0.3,
      delta: 1e-6,
      noiseMechanism: NoiseMechanism.GAUSSIAN,
      compositionTheorem: CompositionTheorem.MOMENTS_ACCOUNTANT,
      budgetAllocationMethod: BudgetAllocationMethod.IMPORTANCE,
      ...options
    });
  }

  static forMultipleQueries(options = {}) {
    return new DifferentialPrivacy({
      epsilon: 2.0,
      delta: 1e-6,
      noiseMechanism: NoiseMechanism.GAUSSIAN,
      compositionTheorem: CompositionTheorem.MOMENTS_ACCOUNTANT,
      budgetAllocationMethod: BudgetAllocationMethod.ADAPTIVE,
      ...options
    });
  }

  static forDomainRange(lower, upper, options = {}) {
    const range = upper - lower;
    return new DifferentialPrivacy({
      epsilon: 1.0,
      sensitivity: range,
      noiseMechanism: NoiseMechanism.LAPLACE,
      ...options
    });
  }
}

// Export components
module.exports = {
  DifferentialPrivacy,
  DPFactory,
  NoiseMechanism,
  BudgetAllocationMethod,
  CompositionTheorem
};
