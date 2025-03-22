/**
 * @fileoverview Privacy workflow tests for PrivaSight
 * 
 * This test suite focuses specifically on testing all privacy mechanisms
 * and workflows in PrivaSight, ensuring that data privacy is maintained
 * throughout all operations.
 */

const crypto = require('crypto');
const assert = require('assert');

// Import PrivaSight modules
const { RegressionModel, RegressionType } = require('../regression');
const { ClusteringModel } = require('../clustering');
const { FederatedLearning, FederatedClient, PrivacyMechanism } = require('../federated-learning');
const { DifferentialPrivacy, DPFactory, NoiseMechanism } = require('../differential-privacy');
const { SecretSharing } = require('../../smpc/secret-sharing');
const { Coordinator } = require('../../smpc/coordinator');
const { PrivacyLayer } = require('../privacy-layer');
const { PrivacyBudget } = require('../privacy-budget');
const { PrivacyAudit } = require('../privacy-audit');

// Test configuration
const TEST_TIMEOUT = 30000; // 30 seconds for longer privacy tests
const EPSILON_VALUES = [0.1, 0.5, 1.0, 5.0];
const DELTA_VALUES = [1e-6, 1e-5];

/**
 * Generate synthetic sensitive data
 * @param {number} numSamples - Number of data points to generate
 * @param {number} dimensionality - Number of features per sample
 * @param {number} numSensitiveColumns - Number of columns that contain sensitive data
 * @returns {Object} Generated data with sensitivity information
 */
function generateSensitiveData(numSamples, dimensionality, numSensitiveColumns) {
  const data = [];
  const sensitiveColumns = [];
  
  // Randomly select sensitive columns
  while (sensitiveColumns.length < numSensitiveColumns) {
    const col = Math.floor(Math.random() * dimensionality);
    if (!sensitiveColumns.includes(col)) {
      sensitiveColumns.push(col);
    }
  }
  
  // Generate data
  for (let i = 0; i < numSamples; i++) {
    const sample = Array(dimensionality).fill(0).map((_, j) => {
      // Sensitive columns have a different distribution
      return sensitiveColumns.includes(j) ? Math.random() * 100 : Math.random() * 10;
    });
    data.push(sample);
  }
  
  // Define sensitivity
  const columnSensitivity = Array(dimensionality).fill(1);
  sensitiveColumns.forEach(col => {
    columnSensitivity[col] = 10; // Higher sensitivity for sensitive columns
  });
  
  return { data, sensitiveColumns, columnSensitivity };
}

/**
 * Utility to measure privacy leakage
 * @param {Array} originalData - Original sensitive data
 * @param {Array} processedData - Data after privacy mechanism
 * @param {Array} sensitiveColumns - Indices of sensitive columns
 * @returns {Object} Privacy leakage metrics
 */
function measurePrivacyLeakage(originalData, processedData, sensitiveColumns) {
  if (originalData.length !== processedData.length) {
    throw new Error('Data dimension mismatch');
  }
  
  const metrics = {
    meanAbsoluteError: 0,
    maxError: 0,
    sensitiveLeakage: 0,
    nonSensitiveLeakage: 0
  };
  
  let sensitiveCount = 0;
  let nonSensitiveCount = 0;
  
  for (let i = 0; i < originalData.length; i++) {
    const original = originalData[i];
    const processed = processedData[i];
    
    if (!processed || original.length !== processed.length) continue;
    
    for (let j = 0; j < original.length; j++) {
      const error = Math.abs(original[j] - processed[j]);
      metrics.meanAbsoluteError += error;
      metrics.maxError = Math.max(metrics.maxError, error);
      
      if (sensitiveColumns.includes(j)) {
        metrics.sensitiveLeakage += error;
        sensitiveCount++;
      } else {
        metrics.nonSensitiveLeakage += error;
        nonSensitiveCount++;
      }
    }
  }
  
  const totalElements = originalData.length * originalData[0].length;
  metrics.meanAbsoluteError /= totalElements;
  if (sensitiveCount > 0) metrics.sensitiveLeakage /= sensitiveCount;
  if (nonSensitiveCount > 0) metrics.nonSensitiveLeakage /= nonSensitiveCount;
  
  return metrics;
}

/**
 * Utility to verify statistical guarantees of differential privacy
 * @param {Function} mechanism - Privacy mechanism function to test
 * @param {number} epsilon - Privacy parameter
 * @param {number} trials - Number of statistical trials
 * @returns {boolean} Whether the mechanism satisfies DP guarantees
 */
function verifyDifferentialPrivacy(mechanism, epsilon, trials = 1000) {
  const baseDataset = Array.from({ length: 100 }, () => Math.random() * 10);
  const outputRatios = [];
  
  for (let i = 0; i < trials; i++) {
    const dataset1 = [...baseDataset];
    const dataset2 = [...baseDataset];
    dataset2[0] = Math.random() * 10; // Change one element
    
    const output1 = mechanism(dataset1);
    const output2 = mechanism(dataset2);
    
    if (output1 !== 0 && output2 !== 0) {
      const ratio = Math.abs(Math.log(output1 / output2));
      outputRatios.push(ratio);
    }
  }
  
  const maxRatio = Math.max(...outputRatios);
  const confidenceMargin = 1.05; // 5% margin for statistical noise
  return maxRatio <= (epsilon * confidenceMargin);
}

// Main test suite
describe('PrivaSight Privacy Workflow Tests', () => {
  jest.setTimeout(TEST_TIMEOUT);
  
  beforeAll(async () => {
    await PrivacyLayer.initialize();
    await Coordinator.initialize();
  });
  
  afterAll(async () => {
    await PrivacyLayer.cleanup();
    await Coordinator.cleanup();
  });
  
  ### Differential Privacy Mechanisms
  describe('Differential Privacy Mechanisms', () => {
    test('Laplace mechanism preserves privacy at different epsilon values', () => {
      for (const epsilon of EPSILON_VALUES) {
        const dp = new DifferentialPrivacy({
          epsilon,
          sensitivity: 1.0,
          noiseMechanism: NoiseMechanism.LAPLACE
        });
        
        const { data, sensitiveColumns } = generateSensitiveData(100, 5, 2);
        const privatized = data.map(sample => sample.map(value => dp.addLaplaceNoise(value)));
        
        const leakage = measurePrivacyLeakage(data, privatized, sensitiveColumns);
        if (epsilon <= 0.5) expect(leakage.meanAbsoluteError).toBeGreaterThan(1.0);
        
        const laplaceMechanism = (dataset) => {
          const sum = dataset.reduce((a, b) => a + b, 0);
          return dp.addLaplaceNoise(sum, 1.0);
        };
        
        const satisfiesDp = verifyDifferentialPrivacy(laplaceMechanism, epsilon);
        expect(satisfiesDp).toBe(true);
      }
    });
    
    test('Gaussian mechanism preserves privacy at different (epsilon,delta) pairs', () => {
      for (const epsilon of EPSILON_VALUES) {
        for (const delta of DELTA_VALUES) {
          const dp = new DifferentialPrivacy({
            epsilon,
            delta,
            sensitivity: 1.0,
            noiseMechanism: NoiseMechanism.GAUSSIAN
          });
          
          const { data, sensitiveColumns } = generateSensitiveData(100, 5, 2);
          const privatized = data.map(sample => sample.map(value => dp.addGaussianNoise(value)));
          
          const leakage = measurePrivacyLeakage(data, privatized, sensitiveColumns);
          const expectedNoiseLevel = 1 / epsilon;
          expect(leakage.meanAbsoluteError).toBeGreaterThan(expectedNoiseLevel * 0.1);
          
          const budgetStats = dp.getBudgetStatistics();
          expect(budgetStats.remainingBudget).toBeLessThan(epsilon);
        }
      }
    });
    
    test('Privacy budget is properly tracked and enforced', () => {
      const initialEpsilon = 1.0;
      const dp = new DifferentialPrivacy({
        epsilon: initialEpsilon,
        maxBudget: initialEpsilon,
        autoReset: false
      });
      
      const values = [5, 10, 15, 20, 25];
      const results = [];
      
      for (const value of values) {
        if (dp.hasSufficientBudget(0.2)) {
          results.push(dp.addLaplaceNoise(value, 1.0, 0.2));
        } else {
          break;
        }
      }
      
      expect(results.length).toBeLessThan(values.length);
      
      const budgetStats = dp.getBudgetStatistics();
      expect(budgetStats.remainingBudget).toBeLessThanOrEqual(0.2);
      
      expect(() => dp.addLaplaceNoise(30, 1.0, 0.2)).toThrow(/budget/);
      
      dp.resetPrivacyBudget();
      expect(dp.hasSufficientBudget(0.2)).toBe(true);
    });
    
    test('Different composition theorems provide different privacy guarantees', () => {
      const epsilon = 0.1;
      const delta = 1e-6;
      const queryCount = 100;
      
      const basicDp = new DifferentialPrivacy({
        epsilon,
        delta,
        compositionTheorem: 'BASIC',
        maxBudget: epsilon * queryCount
      });
      
      const advancedDp = new DifferentialPrivacy({
        epsilon,
        delta,
        compositionTheorem: 'ADVANCED',
        maxBudget: epsilon * queryCount
      });
      
      const renyiDp = new DifferentialPrivacy({
        epsilon,
        delta,
        compositionTheorem: 'RENYI',
        maxBudget: epsilon * queryCount
      });
      
      const values = Array.from({ length: queryCount }, (_, i) => i * 10);
      
      let basicQueries = 0, advancedQueries = 0, renyiQueries = 0;
      
      for (const value of values) {
        if (basicDp.hasSufficientBudget(epsilon)) {
          basicDp.addLaplaceNoise(value, 1.0, epsilon);
          basicQueries++;
        }
        if (advancedDp.hasSufficientBudget(epsilon)) {
          advancedDp.addLaplaceNoise(value, 1.0, epsilon);
          advancedQueries++;
        }
        if (renyiDp.hasSufficientBudget(epsilon)) {
          renyiDp.addLaplaceNoise(value, 1.0, epsilon);
          renyiQueries++;
        }
      }
      
      expect(advancedQueries).toBeGreaterThan(basicQueries);
      expect(renyiQueries).toBeGreaterThan(advancedQueries);
    });
  });
  
  ### Secure Multi-Party Computation
  describe('Secure Multi-Party Computation', () => {
    test('SMPC preserves privacy during joint computation', async () => {
      const secretSharing = new SecretSharing();
      const party1Data = [10, 20, 30, 40, 50];
      const party2Data = [5, 15, 25, 35, 45];
      const party3Data = [2, 12, 22, 32, 42];
      
      const trueSum = party1Data.reduce((a, b) => a + b, 0) +
                      party2Data.reduce((a, b) => a + b, 0) +
                      party3Data.reduce((a, b) => a + b, 0);
      
      const party1Shares = await secretSharing.createShares(party1Data, 3, 2);
      const party2Shares = await secretSharing.createShares(party2Data, 3, 2);
      const party3Shares = await secretSharing.createShares(party3Data, 3, 2);
      
      const computeShare = (share1, share2, share3) => {
        return share1.map((v, i) => v + share2[i] + share3[i]);
      };
      
      const resultShares = [
        computeShare(party1Shares[0], party2Shares[0], party3Shares[0]),
        computeShare(party1Shares[1], party2Shares[1], party3Shares[1]),
        computeShare(party1Shares[2], party2Shares[2], party3Shares[2])
      ];
      
      const secureSum = await secretSharing.reconstructSecret(resultShares);
      expect(secureSum.reduce((a, b) => a + b, 0)).toEqual(trueSum);
      
      const attempt = await secretSharing.reconstructSecret([party1Shares[0], party2Shares[0]]);
      expect(attempt).not.toEqual(party3Data);
    });
    
    test('SMPC with differential privacy provides double protection', async () => {
      const secretSharing = new SecretSharing();
      const dp = new DifferentialPrivacy({ epsilon: 1.0 });
      const sensitiveData = Array.from({ length: 100 }, () => Math.random() * 100);
      
      const privatizedData = sensitiveData.map(value => dp.addLaplaceNoise(value));
      const shares = await secretSharing.createShares(privatizedData, 3, 2);
      const result = await secretSharing.reconstructSecret(shares);
      
      const secureAvg = result.reduce((a, b) => a + b, 0) / result.length;
      const trueAvg = sensitiveData.reduce((a, b) => a + b, 0) / sensitiveData.length;
      const errorMargin = 5.0 / Math.sqrt(sensitiveData.length);
      expect(Math.abs(secureAvg - trueAvg)).toBeLessThan(errorMargin * 3);
      
      const individualErrors = sensitiveData.map((value, i) => Math.abs(value - result[i]));
      const avgIndividualError = individualErrors.reduce((a, b) => a + b, 0) / individualErrors.length;
      expect(avgIndividualError).toBeGreaterThan(0.5);
    });
  });
  
  ### Federated Learning Privacy
  describe('Federated Learning Privacy', () => {
    test('Federated learning preserves privacy during model training', async () => {
      const coordinator = new FederatedLearning({
        modelType: 'REGRESSION',
        numRounds: 3,
        minParticipants: 2,
        privacyMechanism: PrivacyMechanism.DIFFERENTIAL_PRIVACY,
        epsilon: 1.0,
        delta: 1e-6
      });
      
      const numClients = 3;
      const clients = [];
      const clientData = [];
      
      for (let i = 0; i < numClients; i++) {
        const samples = 50;
        const data = Array.from({ length: samples }, () => [Math.random() * 10]);
        const labels = data.map(([x]) => 2 * x + 1 + (Math.random() - 0.5));
        clientData.push({ data, labels });
        
        const client = new FederatedClient({
          clientId: `client-${i}`,
          localData: data,
          localLabels: labels,
          differentialPrivacy: true,
          epsilon: 1.0,
          clippingThreshold: 1.0
        });
        
        clients.push(client);
        coordinator.registerClient(`client-${i}`, { datasetSize: samples });
      }
      
      const initialModel = { weights: [0], intercept: 0 };
      coordinator.initializeGlobalModel(initialModel);
      
      for (let round = 0; round < coordinator.numRounds; round++) {
        const clientUpdates = clients.map(client => {
          client.receiveGlobalModel(coordinator.getGlobalModel());
          client.trainLocalModel();
          return { 
            clientId: client.clientId, 
            datasetSize: client.trainingData.length, 
            update: client.computeModelUpdate() 
          };
        });
        
        clientUpdates.forEach(update => 
          coordinator.simulateClientUpdate(update.clientId, update.update, { datasetSize: update.datasetSize })
        );
      }
      
      const finalModel = coordinator.getGlobalModel();
      expect(finalModel.weights[0]).toBeCloseTo(2, 1);
      expect(finalModel.intercept).toBeCloseTo(1, 1);
      
      let memorizedCount = 0;
      let reconstructionError = 0;
      const totalSamples = clientData.reduce((sum, cd) => sum + cd.data.length, 0);
      
      clientData.forEach(({ data, labels }) => {
        data.forEach(([x], j) => {
          const trueY = labels[j];
          const predictedY = finalModel.weights[0] * x + finalModel.intercept;
          reconstructionError += Math.abs(predictedY - trueY);
          if (Math.abs(predictedY - trueY) < 0.01) memorizedCount++;
        });
      });
      
      reconstructionError /= totalSamples;
      const memorizedFraction = memorizedCount / totalSamples;
      
      expect(reconstructionError).toBeGreaterThan(0.1);
      expect(memorizedFraction).toBeLessThan(0.1);
      
      const stats = coordinator.getStatistics();
      expect(stats.privacyBudgetUsed).toBeGreaterThan(0);
      expect(stats.privacyBudgetUsed).toBeLessThanOrEqual(coordinator.epsilon);
    });
  });
  
  ### Privacy Layer Integration
  describe('Privacy Layer Integration', () => {
    test('Privacy Layer enforces appropriate privacy mechanisms', async () => {
      const sensitiveData = Array.from({ length: 100 }, () => 
        Array.from({ length: 5 }, () => Math.random() * 100)
      );
      
      const request = {
        operation: 'REGRESSION',
        data: sensitiveData,
        privacy: { enableDP: true, epsilon: 0.5, delta: 1e-6 }
      };
      
      const result = await PrivacyLayer.processRequest(request);
      expect(result).toHaveProperty('privacyMetrics');
      expect(result.privacyMetrics).toHaveProperty('epsilon', 0.5);
      
      const data = sensitiveData.map(row => row.slice(0, -1));
      const labels = sensitiveData.map(row => row[row.length - 1]);
      const model = new RegressionModel({ type: RegressionType.LINEAR, enableDP: false });
      await model.train({ data, labels });
      const nonPrivateModel = model.export();
      
      expect(result.model.weights.length).toEqual(nonPrivateModel.weights.length);
      const hasDifference = nonPrivateModel.weights.some((w, i) => 
        Math.abs(w - result.model.weights[i]) > 0.01
      );
      expect(hasDifference).toBe(true);
    });
    
    test('Privacy audit log correctly tracks operations', async () => {
      await PrivacyAudit.initialize();
      const request = {
        userId: 'user123',
        researcherId: 'researcher456',
        dataId: 'dataset789',
        operation: 'CLUSTERING',
        privacy: { enableDP: true, epsilon: 1.0, mechanism: 'GAUSSIAN' }
      };
      
      await PrivacyAudit.logOperation(request);
      const auditLog = await PrivacyAudit.getOperationLog('dataset789');
      expect(auditLog.length).toBeGreaterThan(0);
      expect(auditLog[0]).toHaveProperty('userId', 'user123');
      expect(auditLog[0]).toHaveProperty('researcherId', 'researcher456');
      expect(auditLog[0]).toHaveProperty('operation', 'CLUSTERING');
      expect(auditLog[0].privacy).toHaveProperty('epsilon', 1.0);
      
      const budgetUsage = await PrivacyAudit.getPrivacyBudgetUsage('dataset789');
      expect(budgetUsage).toHaveProperty('used');
      expect(budgetUsage.used).toBeGreaterThan(0);
    });
    
    test('Privacy budget manager enforces limits across operations', async () => {
      await PrivacyBudget.initialize();
      const datasetId = 'limitedDataset';
      const budgetLimit = 3.0;
      await PrivacyBudget.setBudgetLimit(datasetId, budgetLimit);
      
      const operations = [
        { epsilon: 1.0, operation: 'REGRESSION' },
        { epsilon: 1.0, operation: 'CLUSTERING' },
        { epsilon: 0.5, operation: 'STATISTICS' }
      ];
      
      for (const op of operations) {
        await PrivacyBudget.usePrivacyBudget(datasetId, op.epsilon, op.operation);
      }
      
      const remaining = await PrivacyBudget.getRemainingBudget(datasetId);
      expect(remaining).toBeCloseTo(budgetLimit - 2.5, 1);
      
      const exceededOp = { epsilon: 1.0, operation: 'FEDERATED' };
      await expect(
        PrivacyBudget.usePrivacyBudget(datasetId, exceededOp.epsilon, exceededOp.operation)
      ).rejects.toThrow(/budget/);
      
      const finalRemaining = await PrivacyBudget.getRemainingBudget(datasetId);
      expect(finalRemaining).toBeCloseTo(budgetLimit - 2.5, 1);
    });
  });
  
  ### Data Minimization and Purpose Limitation
  describe('Data Minimization and Purpose Limitation', () => {
    test('Privacy Layer applies appropriate data minimization', async () => {
      const data = Array.from({ length: 50 }, (_, i) => ({
        id: `user${i}`,
        name: `Person ${i}`,
        email: `person${i}@example.com`,
        age: 20 + Math.floor(Math.random() * 50),
        income: 30000 + Math.floor(Math.random() * 70000),
        zipCode: `${10000 + Math.floor(Math.random() * 80000)}`,
        healthMetric: Math.floor(Math.random() * 100)
      }));
      
      const request = {
        operation: 'STATISTICS',
        purpose: 'AGE_INCOME_ANALYSIS',
        data,
        requiredAttributes: ['age', 'income'],
        privacy: { enableDP: true, epsilon: 1.0 }
      };
      
      const result = await PrivacyLayer.processRequest(request);
      expect(result).toHaveProperty('filteredAttributes');
      expect(result.filteredAttributes).toContain('age');
      expect(result.filteredAttributes).toContain('income');
      expect(result.filteredAttributes).not.toContain('name');
      expect(result.filteredAttributes).not.toContain('email');
      expect(result.filteredAttributes).not.toContain('zipCode');
      
      if (result.data) {
        const sampleRecord = result.data[0];
        expect(sampleRecord).not.toHaveProperty('name');
        expect(sampleRecord).not.toHaveProperty('email');
        expect(sampleRecord).toHaveProperty('age');
        expect(sampleRecord).toHaveProperty('income');
      }
    });
  });
});
