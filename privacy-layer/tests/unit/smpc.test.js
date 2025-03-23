/**
 * @fileoverview Secure Multi-Party Computation (SMPC) tests for PrivaSight
 *
 * These tests verify the functionality, security, and performance of PrivaSight's
 * SMPC components, enabling collaborative computation across multiple parties
 * without sharing raw data.
 */

const crypto = require('crypto');
const { SMPCCoordinator } = require('../../smpc/coordinator');
const { SMPCNode } = require('../../smpc/node');
const { SecretSharing } = require('../../smpc/secret-sharing');
const { PrivacyLayer } = require('../privacy-layer');
const { DifferentialPrivacy } = require('../differential-privacy');

// Test configuration
const TEST_TIMEOUT = 30000; // 30 seconds for potentially intensive SMPC tests

/**
 * Generate a random integer between min and max
 * @param {number} min - Minimum value (inclusive)
 * @param {number} max - Maximum value (exclusive)
 * @returns {number} Random integer
 */
function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min)) + min);
}

/**
 * Generate a random array of integers
 * @param {number} length - Array length
 * @param {number} min - Minimum value (inclusive)
 * @param {number} max - Maximum value (exclusive)
 * @returns {Array<number>} Random array
 */
function randomArray(length, min, max) {
  return Array.from({ length }, () => randomInt(min, max));
}

// Main test suite
describe('PrivaSight SMPC Component Tests', () => {
  jest.setTimeout(TEST_TIMEOUT);

  let coordinator;
  let nodes = [];
  const numNodes = 3;

  // Setup before all tests
  beforeAll(async () => {
    coordinator = new SMPCCoordinator();
    await coordinator.initialize({ threshold: 2, numParties: numNodes });

    for (let i = 0; i < numNodes; i++) {
      const node = new SMPCNode(`node-${i}`);
      await node.initialize({ coordinatorId: coordinator.id });
      nodes.push(node);
      await coordinator.registerNode(node.id, { capabilities: node.capabilities });
    }
  });

  // Cleanup after all tests
  afterAll(async () => {
    await coordinator.shutdown();
    for (const node of nodes) {
      await node.shutdown();
    }
  });

  describe('SMPC Protocol Tests', () => {
    test('Should perform secure set intersection without revealing inputs', async () => {
      // Generate sets with some overlap
      const baseSets = [
        new Set([1, 2, 3, 4, 5]),
        new Set([3, 4, 5, 6, 7]),
        new Set([5, 6, 7, 8, 9]),
      ];
      const expectedIntersection = new Set([5]);

      // Setup computation
      const computationId = await coordinator.setupComputation({
        type: 'SET_INTERSECTION',
        participants: nodes.map((node) => node.id),
      });

      // Nodes contribute their data
      const contributePromises = nodes.map((node, i) =>
        node.contributeToComputation(computationId, { set: Array.from(baseSets[i]) })
      );
      await Promise.all(contributePromises);

      // Run computation
      await coordinator.runComputation(computationId);

      // Get result
      const result = await coordinator.getComputationResult(computationId);

      // Verify result
      expect(result).toHaveProperty('intersection');
      expect(new Set(result.intersection)).toEqual(expectedIntersection);

      // Verify original sets were not revealed
      expect(result).not.toHaveProperty('inputs');
      expect(result).not.toHaveProperty('sets');

      // Check computation logs for privacy
      const logs = await coordinator.getComputationLogs(computationId);
      for (const log of logs) {
        expect(log).not.toContain(JSON.stringify(baseSets[0]));
        expect(log).not.toContain(JSON.stringify(baseSets[1]));
        expect(log).not.toContain(JSON.stringify(baseSets[2]));
      }
    });

    test('Should compute secure statistics on distributed data', async () => {
      // Generate random data for each node
      const nodeDatas = [
        [10, 20, 30, 40, 50],
        [15, 25, 35, 45, 55],
        [5, 15, 25, 35, 45],
      ];

      // Calculate expected results
      const allData = nodeDatas.flat();
      const expectedMean = allData.reduce((sum, val) => sum + val, 0) / allData.length;
      const expectedMin = Math.min(...allData);
      const expectedMax = Math.max(...allData);
      const variance =
        allData.reduce((sum, val) => sum + Math.pow(val - expectedMean, 2), 0) / allData.length;
      const expectedStdDev = Math.sqrt(variance);

      // Setup computation
      const computationId = await coordinator.setupComputation({
        type: 'SECURE_STATISTICS',
        participants: nodes.map((node) => node.id),
        config: {
          statistics: ['mean', 'min', 'max', 'stddev'],
        },
      });

      // Nodes contribute their data
      const contributePromises = nodes.map((node, i) =>
        node.contributeToComputation(computationId, { values: nodeDatas[i] })
      );
      await Promise.all(contributePromises);

      // Run computation
      await coordinator.runComputation(computationId);

      // Get result
      const result = await coordinator.getComputationResult(computationId);

      // Verify results
      expect(result).toHaveProperty('statistics');
      expect(result.statistics.mean).toBeCloseTo(expectedMean, 5);
      expect(result.statistics.min).toBe(expectedMin);
      expect(result.statistics.max).toBe(expectedMax);
      expect(result.statistics.stddev).toBeCloseTo(expectedStdDev, 5);

      // Verify raw data privacy
      expect(result).not.toHaveProperty('inputs');
      expect(result).not.toHaveProperty('values');

      // Each node should only see its own contribution + final result
      for (let i = 0; i < nodes.length; i++) {
        const nodeContribution = await nodes[i].getContribution(computationId);
        expect(nodeContribution).toHaveProperty('values');
        expect(nodeContribution.values).toEqual(nodeDatas[i]);
        for (let j = 0; j < nodes.length; j++) {
          if (i !== j) {
            expect(nodeContribution).not.toHaveProperty(`node-${j}`);
          }
        }
      }
    });

    test('Should perform secure machine learning on distributed data', async () => {
      // Generate synthetic linear regression data: y = 2x + 1 + noise
      const generateLinearData = (numSamples) => {
        const data = [];
        const labels = [];
        for (let i = 0; i < numSamples; i++) {
          const x = Math.random() * 10;
          const noise = (Math.random() - 0.5) * 0.5;
          const y = 2 * x + 1 + noise;
          data.push([x]);
          labels.push(y);
        }
        return { data, labels };
      };

      const nodeData = nodes.map(() => generateLinearData(20));

      // Setup computation
      const computationId = await coordinator.setupComputation({
        type: 'SECURE_LINEAR_REGRESSION',
        participants: nodes.map((node) => node.id),
        config: {
          epochs: 10,
          learningRate: 0.01,
          enableDP: true,
          epsilon: 1.0,
        },
      });

      // Nodes contribute their data
      const contributePromises = nodes.map((node, i) =>
        node.contributeToComputation(computationId, nodeData[i])
      );
      await Promise.all(contributePromises);

      // Run computation
      await coordinator.runComputation(computationId);

      // Get result
      const result = await coordinator.getComputationResult(computationId);

      // Verify model parameters
      expect(result).toHaveProperty('model');
      expect(result.model).toHaveProperty('weights');
      expect(result.model).toHaveProperty('intercept');
      expect(result.model.weights[0]).toBeCloseTo(2, 0); // Allowing deviation due to noise/DP
      expect(result.model.intercept).toBeCloseTo(1, 0);

      // Verify raw data privacy
      expect(result).not.toHaveProperty('data');
      expect(result).not.toHaveProperty('labels');
      expect(result).not.toHaveProperty('inputs');

      // Test model on new data
      const testData = [[3], [5], [7]];
      const expectedPredictions = testData.map(([x]) => 2 * x + 1);
      const testResult = await coordinator.testModel(computationId, testData);
      expect(testResult).toHaveProperty('predictions');
      for (let i = 0; i < testData.length; i++) {
        expect(testResult.predictions[i]).toBeCloseTo(expectedPredictions[i], 0);
      }
    });

    test('Should compute secure database join without revealing raw data', async () => {
      // Setup data for secure join
      const table1 = [
        { id: 1, name: 'Alice' },
        { id: 2, name: 'Bob' },
        { id: 3, name: 'Charlie' },
        { id: 4, name: 'Diana' },
      ];
      const table2 = [
        { id: 2, salary: 75000 },
        { id: 3, salary: 85000 },
        { id: 4, salary: 95000 },
        { id: 5, salary: 105000 },
      ];
      const expectedJoin = [
        { id: 2, name: 'Bob', salary: 75000 },
        { id: 3, name: 'Charlie', salary: 85000 },
        { id: 4, name: 'Diana', salary: 95000 },
      ];

      // Setup computation
      const computationId = await coordinator.setupComputation({
        type: 'SECURE_JOIN',
        participants: [nodes[0].id, nodes[1].id], // Using two nodes
        config: {
          joinColumn: 'id',
          joinType: 'INNER',
        },
      });

      // Nodes contribute their data
      await nodes[0].contributeToComputation(computationId, { table: table1 });
      await nodes[1].contributeToComputation(computationId, { table: table2 });

      // Run computation
      await coordinator.runComputation(computationId);

      // Get result
      const result = await coordinator.getComputationResult(computationId);

      // Verify join result
      expect(result).toHaveProperty('joinedTable');
      expect(result.joinedTable.length).toBe(expectedJoin.length);

      // Compare results, accounting for possible different ordering
      const sortById = (a, b) => a.id - b.id;
      const sortedResult = result.joinedTable.sort(sortById);
      const sortedExpected = expectedJoin.sort(sortById);
      for (let i = 0; i < sortedExpected.length; i++) {
        expect(sortedResult[i].id).toBe(sortedExpected[i].id);
        expect(sortedResult[i].name).toBe(sortedExpected[i].name);
        expect(sortedResult[i].salary).toBe(sortedExpected[i].salary);
      }

      // Verify privacy
      expect(result).not.toHaveProperty('tables');
      expect(result).not.toHaveProperty('inputs');

      // Verify node-specific data views
      const node1View = await nodes[0].getContribution(computationId);
      const node2View = await nodes[1].getContribution(computationId);
      expect(node1View).toHaveProperty('table');
      expect(node1View.table).toEqual(table1);
      expect(node1View).not.toHaveProperty('otherTables');
      expect(node2View).toHaveProperty('table');
      expect(node2View.table).toEqual(table2);
      expect(node2View).not.toHaveProperty('otherTables');
    });
  });

  describe('Differential Privacy Integration Tests', () => {
    test('Should correctly implement differentially private SMPC', async () => {
      // Generate random data
      const nodeDatas = nodes.map(() => randomArray(30, 0, 100));
      const allData = nodeDatas.flat();
      const trueMean = allData.reduce((sum, val) => sum + val, 0) / allData.length;

      // Test with varying epsilon values
      const epsilonValues = [0.1, 1.0, 10.0];
      const results = [];

      for (const epsilon of epsilonValues) {
        const computationId = await coordinator.setupComputation({
          type: 'DP_SECURE_MEAN',
          participants: nodes.map((node) => node.id),
          config: {
            epsilon,
            delta: 1e-6,
          },
        });

        // Nodes contribute data
        const contributePromises = nodes.map((node, i) =>
          node.contributeToComputation(computationId, { values: nodeDatas[i] })
        );
        await Promise.all(contributePromises);

        // Run computation
        await coordinator.runComputation(computationId);

        // Get result
        const result = await coordinator.getComputationResult(computationId);
        results.push({ epsilon, mean: result.mean });
      }

      // Verify that as epsilon increases, results approach true mean
      const errorsByEpsilon = results.map((r) => Math.abs(r.mean - trueMean));
      for (let i = 1; i < errorsByEpsilon.length; i++) {
        expect(errorsByEpsilon[i]).toBeLessThanOrEqual(errorsByEpsilon[i - 1] * 2);
      }
      expect(results[results.length - 1].mean).toBeCloseTo(trueMean, 0);
    });

    test('Should implement advanced composition for multi-query privacy budget', async () => {
      // Generate structured data
      const nodeData = nodes.map(() => {
        const data = [];
        for (let i = 0; i < 50; i++) {
          data.push({
            age: randomInt(20, 80),
            income: randomInt(30000, 200000),
            education: randomInt(10, 20),
          });
        }
        return data;
      });

      // Setup privacy budget
      const totalEpsilon = 1.0;
      const delta = 1e-6;
      const numQueries = 3;
      const dpManager = new DifferentialPrivacy({
        epsilon: totalEpsilon,
        delta,
        compositionTheorem: 'ADVANCED',
      });

      // Setup computation
      const computationId = await coordinator.setupComputation({
        type: 'MULTI_QUERY_DP',
        participants: nodes.map((node) => node.id),
        config: { totalEpsilon, delta, numQueries },
      });

      // Nodes contribute data
      const contributePromises = nodes.map((node, i) =>
        node.contributeToComputation(computationId, { records: nodeData[i] })
      );
      await Promise.all(contributePromises);

      // Run multiple queries
      const queries = [
        { attribute: 'age', statistic: 'mean' },
        { attribute: 'income', statistic: 'mean' },
        { attribute: 'education', statistic: 'mean' },
      ];
      const queryResults = [];

      for (const query of queries) {
        const queryEpsilon = dpManager.allocatePrivacyBudget(totalEpsilon / numQueries);
        const queryResult = await coordinator.executeQuery(computationId, {
          ...query,
          epsilon: queryEpsilon,
        });
        queryResults.push(queryResult);
      }

      // Verify query results
      expect(queryResults.length).toBe(numQueries);
      for (const result of queryResults) {
        expect(result).toHaveProperty('result');
        expect(typeof result.result).toBe('number');
      }

      // Verify budget exhaustion
      const budgetRemaining = dpManager.getRemainingBudget();
      expect(budgetRemaining).toBeCloseTo(0, 5);

      // Additional query should fail
      await expect(
        coordinator.executeQuery(computationId, {
          attribute: 'age',
          statistic: 'variance',
          epsilon: 0.1,
        })
      ).rejects.toThrow(/privacy budget/i);
    });

    test('Should integrate local and global differential privacy', async () => {
      // Generate data
      const nodeData = nodes.map(() => randomArray(20, 0, 100));
      const allData = nodeData.flat();
      const trueMean = allData.reduce((sum, val) => sum + val, 0) / allData.length;

      // Setup two-level DP computation
      const computationId = await coordinator.setupComputation({
        type: 'TWO_LEVEL_DP',
        participants: nodes.map((node) => node.id),
        config: {
          localEpsilon: 1.0,
          globalEpsilon: 0.5,
          delta: 1e-6,
        },
      });

      // Nodes contribute with local DP
      const contributePromises = nodes.map(async (node, i) => {
        const localDP = new DifferentialPrivacy({ epsilon: 1.0, delta: 1e-6 });
        const localSum = nodeData[i].reduce((sum, val) => sum + val, 0);
        const noisySum = localDP.addLaplaceNoise(localSum, nodeData[i].length);
        return node.contributeToComputation(computationId, {
          noisySum,
          count: nodeData[i].length,
        });
      });
      await Promise.all(contributePromises);

      // Run computation with global DP
      await coordinator.runComputation(computationId);

      // Get result
      const result = await coordinator.getComputationResult(computationId);

      // Verify result structure
      expect(result).toHaveProperty('mean');
      expect(result).toHaveProperty('privacyParams');
      expect(result.privacyParams).toHaveProperty('effectiveEpsilon');

      // Verify reasonable accuracy
      const absoluteError = Math.abs(result.mean - trueMean);
      expect(absoluteError).toBeLessThan(20); // Allow for noise

      // Verify effective epsilon
      const effectiveEpsilon = Math.sqrt(Math.pow(1.0, 2) + Math.pow(0.5, 2));
      expect(result.privacyParams.effectiveEpsilon).toBeCloseTo(effectiveEpsilon, 1);
    });
  });

  describe('Security and Performance Tests', () => {
    test('Should be resistant to collusion attacks', async () => {
      const secretSharing = new SecretSharing();
      const secretValue = 42;

      // Threshold 2 out of 3
      const shares = await secretSharing.createShares(secretValue, 3, 2);
      const colludingShares = [shares[0], shares[1]];
      const collusionResult = await secretSharing.reconstructSecret(colludingShares);
      expect(collusionResult).toBe(secretValue); // Succeeds with threshold

      // Threshold 3 out of 5
      const shares2 = await secretSharing.createShares(secretValue, 5, 3);
      const colludingShares2 = [shares2[0], shares2[1]];
      await expect(secretSharing.reconstructSecret(colludingShares2)).rejects.toThrow(
        /insufficient shares/i
      );

      // Collusion-resistant scheme
      const collusionResistantShares = await secretSharing.createCollusionResistantShares(
        secretValue,
        5,
        3
      );
      const colludingResistantShares = [collusionResistantShares[0], collusionResistantShares[1]];
      const extractedInfo = await secretSharing.attemptPartialReconstruction(colludingResistantShares);
      expect(Math.abs(extractedInfo - secretValue)).toBeGreaterThan(10); // No useful info
    });

    test('Should handle malicious adversaries with Byzantine fault tolerance', async () => {
      const computationId = await coordinator.setupComputation({
        type: 'BYZANTINE_TOLERANT_SUM',
        participants: nodes.map((node) => node.id),
        config: { maxMalicious: 1 },
      });

      const honestValues = [10, 20];
      const maliciousValue = 10000;

      // Contribute data
      await nodes[0].contributeToComputation(computationId, { value: honestValues[0] });
      await nodes[1].contributeToComputation(computationId, { value: honestValues[1] });
      await nodes[2].contributeToComputation(computationId, { value: maliciousValue, malicious: true });

      // Run computation
      await coordinator.runComputation(computationId);

      // Get result
      const result = await coordinator.getComputationResult(computationId);

      // Verify robustness
      expect(result).toHaveProperty('robustSum');
      const honestSum = honestValues.reduce((a, b) => a + b, 0);
      expect(result.robustSum).toBeCloseTo(honestSum, 0);
      expect(result).toHaveProperty('standardSum');
      expect(result.standardSum).toBeCloseTo(honestSum + maliciousValue, 0);
      expect(result).toHaveProperty('detectedMalicious');
      expect(result.detectedMalicious).toBe(true);
    });

    test('Should scale performance with number of parties', async () => {
      const numParties = [3, 5, 10];
      const timings = [];

      for (const n of numParties) {
        const parties = [];
        for (let i = 0; i < n; i++) {
          const party = new SMPCNode(`scale-node-${i}`);
          await party.initialize({ coordinatorId: coordinator.id });
          await coordinator.registerNode(party.id, { capabilities: party.capabilities });
          parties.push(party);
        }

        const partyData = parties.map(() => randomInt(1, 100));
        const startTime = Date.now();

        const computationId = await coordinator.setupComputation({
          type: 'SECURE_SUM',
          participants: parties.map((p) => p.id),
        });
        const contributePromises = parties.map((party, i) =>
          party.contributeToComputation(computationId, { value: partyData[i] })
        );
        await Promise.all(contributePromises);
        await coordinator.runComputation(computationId);
        await coordinator.getComputationResult(computationId);

        const endTime = Date.now();
        timings.push({ parties: n, duration: endTime - startTime });

        for (const party of parties) {
          await party.shutdown();
        }
      }

      console.log('SMPC scaling with number of parties:');
      timings.forEach((t) => console.log(`${t.parties} parties: ${t.duration}ms`));

      if (timings.length >= 3) {
        const ratio1 = timings[1].duration / timings[0].duration;
        const ratio2 = timings[2].duration / timings[1].duration;
        const partyRatio1 = timings[1].parties / timings[0].parties;
        const partyRatio2 = timings[2].parties / timings[1].parties;
        const maxExpectedRatio1 = Math.pow(partyRatio1, 2.5);
        const maxExpectedRatio2 = Math.pow(partyRatio2, 2.5);
        expect(ratio1).toBeLessThan(maxExpectedRatio1);
        expect(ratio2).toBeLessThan(maxExpectedRatio2);
      }
    });

    test('Should optimize communication complexity', async () => {
      coordinator.resetCommunicationCounters();
      const computationId = await coordinator.setupComputation({
        type: 'SECURE_SUM',
        participants: nodes.map((node) => node.id),
        config: { trackCommunication: true },
      });

      const nodeData = nodes.map(() => randomInt(1, 100));
      const contributePromises = nodes.map((node, i) =>
        node.contributeToComputation(computationId, { value: nodeData[i] })
      );
      await Promise.all(contributePromises);
      await coordinator.runComputation(computationId);

      const commStats = await coordinator.getCommunicationStats(computationId);
      expect(commStats).toHaveProperty('totalBytes');
      expect(commStats).toHaveProperty('messageCount');
      expect(commStats).toHaveProperty('roundTrips');
      const bytesPerParty = commStats.totalBytes / nodes.length;
      const messagesPerParty = commStats.messageCount / nodes.length;
      expect(bytesPerParty).toBeLessThan(1000);
      expect(messagesPerParty).toBeLessThan(10);

      // Optimized version
      coordinator.resetCommunicationCounters();
      const optimizedId = await coordinator.setupComputation({
        type: 'SECURE_SUM',
        participants: nodes.map((node) => node.id),
        config: { trackCommunication: true, optimizeCommunication: true },
      });
      const optimizedContributePromises = nodes.map((node, i) =>
        node.contributeToComputation(optimizedId, { value: nodeData[i] })
      );
      await Promise.all(optimizedContributePromises);
      await coordinator.runComputation(optimizedId);

      const optimizedStats = await coordinator.getCommunicationStats(optimizedId);
      expect(optimizedStats.totalBytes).toBeLessThan(commStats.totalBytes);
      expect(optimizedStats.messageCount).toBeLessThanOrEqual(commStats.messageCount);
    });
  });

  describe('Integration with Privacy Layer', () => {
    test('Should integrate SMPC with Privacy Layer', async () => {
      const nodeData = [
        { age: 35, income: 75000, region: 'Northeast' },
        { age: 42, income: 85000, region: 'South' },
        { age: 29, income: 65000, region: 'West' },
      ];

      await PrivacyLayer.initialize();
      const requestId = await PrivacyLayer.createSMPCRequest({
        operation: 'SECURE_STATISTICS',
        participants: nodes.map((node) => node.id),
        config: {
          attributes: ['age', 'income'],
          statistics: ['mean', 'median', 'stddev'],
          enableDP: true,
          epsilon: 1.0,
        },
      });

      const contributePromises = nodes.map((node, i) =>
        PrivacyLayer.contributeSMPCData(requestId, node.id, nodeData[i])
      );
      await Promise.all(contributePromises);

      const result = await PrivacyLayer.executeSMPC(requestId);

      expect(result).toHaveProperty('statistics');
      expect(result.statistics).toHaveProperty('age');
      expect(result.statistics.age).toHaveProperty('mean');
      expect(result.statistics.age).toHaveProperty('median');
      expect(result.statistics.age).toHaveProperty('stddev');
      expect(result.statistics).toHaveProperty('income');
      expect(result.statistics.income).toHaveProperty('mean');
      expect(result.statistics.income).toHaveProperty('median');
      expect(result.statistics.income).toHaveProperty('stddev');
      expect(result).toHaveProperty('privacyParams');
      expect(result.privacyParams.epsilon).toBeCloseTo(1.0, 1);
      expect(result).not.toHaveProperty('rawData');
      expect(result).not.toHaveProperty('nodeData');
      expect(result).not.toHaveProperty('inputs');
    });

    test('Should enforce access control for SMPC results', async () => {
      const computationId = await coordinator.setupComputation({
        type: 'SECURE_SUM',
        participants: nodes.map((node) => node.id),
        config: {
          accessControl: {
            allowedUsers: ['researcher1', 'researcher2'],
            requireContribution: true,
          },
        },
      });

      const nodeData = nodes.map(() => randomInt(1, 100));
      const contributePromises = nodes.map((node, i) =>
        node.contributeToComputation(computationId, { value: nodeData[i] })
      );
      await Promise.all(contributePromises);
      await coordinator.runComputation(computationId);

      const authResult = await PrivacyLayer.getComputationResult(computationId, {
        userId: 'researcher1',
      });
      expect(authResult).toHaveProperty('sum');

      await expect(
        PrivacyLayer.getComputationResult(computationId, { userId: 'unauthorized' })
      ).rejects.toThrow(/unauthorized/i);

      const nonContributingNode = new SMPCNode('external-node');
      await nonContributingNode.initialize({ coordinatorId: coordinator.id });
      await coordinator.registerNode(nonContributingNode.id, { capabilities: {} });
      await expect(nonContributingNode.getComputationResult(computationId)).rejects.toThrow(
        /contribution required/i
      );
      await nonContributingNode.shutdown();
    });

    test('Should audit and log SMPC operations securely', async () => {
      await coordinator.enableAuditLogging({ logLevel: 'detailed', privacyAware: true });
      const computationId = await coordinator.setupComputation({
        type: 'SECURE_SUM',
        participants: nodes.map((node) => node.id),
      });

      const nodeData = nodes.map(() => randomInt(1, 100));
      const contributePromises = nodes.map((node, i) =>
        node.contributeToComputation(computationId, { value: nodeData[i] })
      );
      await Promise.all(contributePromises);
      await coordinator.runComputation(computationId);
      const result = await coordinator.getComputationResult(computationId);

      const auditLogs = await coordinator.getAuditLogs(computationId);
      expect(auditLogs.length).toBeGreaterThan(0);

      const eventTypes = auditLogs.map((log) => log.eventType);
      expect(eventTypes).toContain('COMPUTATION_CREATED');
      expect(eventTypes).toContain('CONTRIBUTION_RECEIVED');
      expect(eventTypes).toContain('COMPUTATION_STARTED');
      expect(eventTypes).toContain('COMPUTATION_COMPLETED');
      expect(eventTypes).toContain('RESULT_ACCESSED');

      for (const log of auditLogs) {
        const logStr = JSON.stringify(log);
        for (const value of nodeData) {
          expect(logStr).not.toContain(`"value":${value}`);
          expect(logStr).not.toContain(`"value": ${value}`);
        }
      }

      const resultAccessLogs = auditLogs.filter((log) => log.eventType === 'RESULT_ACCESSED');
      expect(resultAccessLogs.length).toBeGreaterThan(0);
      for (const log of resultAccessLogs) {
        expect(log).toHaveProperty('userId');
        expect(log).toHaveProperty('timestamp');
        expect(log).not.toHaveProperty('result');
      }

      await coordinator.disableAuditLogging();
    });
  });
});
