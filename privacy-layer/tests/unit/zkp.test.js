/**
 * @fileoverview Zero-Knowledge Proof (ZKP) component tests for PrivaSight
 * 
 * These tests verify the functionality and security of PrivaSight's ZKP components
 * which allow data owners to prove statements about their data without revealing
 * the underlying data itself.
 */

const crypto = require('crypto');
const { ZKPProver } = require('../zkp/prover');
const { ZKPVerifier } = require('../zkp/verifier');
const { RangeProof } = require('../zkp/range-proof');
const { SetMembershipProof } = require('../zkp/set-membership');
const { PolynomialProof } = require('../zkp/polynomial');
const { CircuitProof } = require('../zkp/circuit');
const { ZKPAggregator } = require('../zkp/aggregator');
const { PrivacyLayer } = require('../privacy-layer');
const { DataVault } = require('../../blockchain/datavault');

// Test configuration
const TEST_TIMEOUT = 30000; // 30 seconds for ZKP tests which can be computationally intensive

/**
 * Generate random values for testing
 * @param {number} min - Minimum value (inclusive)
 * @param {number} max - Maximum value (exclusive)
 * @returns {number} Random integer between min and max
 */
function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min)) + min;
}

/**
 * Generate a random set of integers
 * @param {number} size - Size of the set
 * @param {number} min - Minimum value (inclusive)
 * @param {number} max - Maximum value (exclusive)
 * @returns {Set<number>} Random set of integers
 */
function randomSet(size, min, max) {
  const set = new Set();
  while (set.size < size) {
    set.add(randomInt(min, max));
  }
  return set;
}

/**
 * Generate a random array of values
 * @param {number} length - Length of array
 * @param {number} min - Minimum value (inclusive)
 * @param {number} max - Maximum value (exclusive)
 * @returns {Array<number>} Random array of integers
 */
function randomArray(length, min, max) {
  return Array.from({ length }, () => randomInt(min, max));
}

// Main test suite
describe('PrivaSight ZKP Component Tests', () => {
  // Increase timeout for ZKP tests
  jest.setTimeout(TEST_TIMEOUT);
  
  // Common variables
  let prover;
  let verifier;
  
  // Setup before tests
  beforeAll(async () => {
    // Initialize ZKP components
    prover = new ZKPProver();
    verifier = new ZKPVerifier();
    
    // Setup necessary crypto parameters
    await prover.initialize();
    await verifier.initialize();
  });
  
  ### Range Proof Tests
  describe('Range Proof Tests', () => {
    test('Should prove value is within valid range', async () => {
      const secretValue = 42;
      const minRange = 0;
      const maxRange = 1000;
      
      const rangeProof = new RangeProof();
      const proof = await rangeProof.generateProof(secretValue, minRange, maxRange);
      const verificationResult = await rangeProof.verifyProof(proof, minRange, maxRange);
      
      expect(verificationResult.verified).toBe(true);
      expect(verificationResult).not.toHaveProperty('value');
      expect(verificationResult).not.toHaveProperty('secretValue');
    });
    
    test('Should reject proof if value is outside range', async () => {
      const secretValue = 2000;
      const minRange = 0;
      const maxRange = 1000;
      
      const rangeProof = new RangeProof();
      const proof = await rangeProof.generateProof(secretValue, minRange, maxRange);
      const verificationResult = await rangeProof.verifyProof(proof, minRange, maxRange);
      
      expect(verificationResult.verified).toBe(false);
    });
    
    test('Should handle multi-dimensional range proofs', async () => {
      const secretValues = [35, 75000];
      const minRanges = [18, 0];
      const maxRanges = [65, 100000];
      
      const rangeProof = new RangeProof();
      const proof = await rangeProof.generateMultiDimensionalProof(secretValues, minRanges, maxRanges);
      const verificationResult = await rangeProof.verifyMultiDimensionalProof(proof, minRanges, maxRanges);
      
      expect(verificationResult.verified).toBe(true);
      
      const invalidSecretValues = [35, 150000];
      const invalidProof = await rangeProof.generateMultiDimensionalProof(invalidSecretValues, minRanges, maxRanges);
      const invalidResult = await rangeProof.verifyMultiDimensionalProof(invalidProof, minRanges, maxRanges);
      
      expect(invalidResult.verified).toBe(false);
    });
  });
  
  ### Set Membership Proof Tests
  describe('Set Membership Proof Tests', () => {
    test('Should prove value is a member of a set', async () => {
      const allowedSet = new Set([10, 20, 30, 40, 50]);
      const secretValue = 30;
      
      const setProof = new SetMembershipProof();
      const proof = await setProof.generateProof(secretValue, allowedSet);
      const verificationResult = await setProof.verifyProof(proof, allowedSet);
      
      expect(verificationResult.verified).toBe(true);
      expect(verificationResult).not.toHaveProperty('value');
    });
    
    test('Should reject proof if value is not in the set', async () => {
      const allowedSet = new Set([10, 20, 30, 40, 50]);
      const secretValue = 35;
      
      const setProof = new SetMembershipProof();
      const proof = await setProof.generateProof(secretValue, allowedSet);
      const verificationResult = await setProof.verifyProof(proof, allowedSet);
      
      expect(verificationResult.verified).toBe(false);
    });
    
    test('Should prove subset membership while hiding which elements', async () => {
      const universeSet = new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
      const secretSubset = new Set([2, 5, 8]);
      
      const setProof = new SetMembershipProof();
      const proof = await setProof.generateSubsetProof(secretSubset, universeSet);
      const verificationResult = await setProof.verifySubsetProof(proof, universeSet);
      
      expect(verificationResult.verified).toBe(true);
      expect(verificationResult.subsetSize).toBe(secretSubset.size);
      expect(verificationResult).not.toHaveProperty('subset');
    });
  });
  
  ### Polynomial Commitment Tests
  describe('Polynomial Commitment Tests', () => {
    test('Should commit to polynomial and prove evaluation point', async () => {
      const polynomial = [5, 2, 3]; // p(x) = 3x^2 + 2x + 5
      const x = 4;
      const expectedY = 5 + 2 * 4 + 3 * 16; // p(4) = 61
      
      const polyProof = new PolynomialProof();
      const commitment = await polyProof.commitToPolynomial(polynomial);
      const proof = await polyProof.proveEvaluation(polynomial, commitment, x);
      const verificationResult = await polyProof.verifyEvaluation(commitment, x, expectedY, proof);
      
      expect(verificationResult.verified).toBe(true);
    });
    
    test('Should reject invalid polynomial evaluation', async () => {
      const polynomial = [5, 2, 3];
      const x = 4;
      const incorrectY = 60;
      
      const polyProof = new PolynomialProof();
      const commitment = await polyProof.commitToPolynomial(polynomial);
      const proof = await polyProof.proveEvaluation(polynomial, commitment, x);
      const verificationResult = await polyProof.verifyEvaluation(commitment, x, incorrectY, proof);
      
      expect(verificationResult.verified).toBe(false);
    });
    
    test('Should perform batched polynomial verification', async () => {
      const polynomials = [[5, 2, 3], [7, 1, 4, 2]];
      const xValues = [4, 3];
      const expectedYValues = [61, 100];
      
      const polyProof = new PolynomialProof();
      const commitments = await Promise.all(polynomials.map(p => polyProof.commitToPolynomial(p)));
      const proofs = await Promise.all(polynomials.map((p, i) => polyProof.proveEvaluation(p, commitments[i], xValues[i])));
      const batchResult = await polyProof.batchVerifyEvaluations(commitments, xValues, expectedYValues, proofs);
      
      expect(batchResult.verified).toBe(true);
      
      const incorrectYValues = [61, 101];
      const incorrectBatchResult = await polyProof.batchVerifyEvaluations(commitments, xValues, incorrectYValues, proofs);
      
      expect(incorrectBatchResult.verified).toBe(false);
    });
  });
  
  ### Circuit-Based ZKP Tests
  describe('Circuit-Based ZKP Tests', () => {
    test('Should prove circuit satisfaction without revealing inputs', async () => {
      const circuit = {
        gates: [
          { type: 'mul', inputs: [0, 1], output: 3 },
          { type: 'add', inputs: [3, 2], output: 4 }
        ],
        publicInputs: [4],
        privateInputs: [0, 1, 2]
      };
      const inputs = [5, 6, 7, 30, 37];
      
      const circuitProof = new CircuitProof();
      const proof = await circuitProof.generateProof(circuit, inputs);
      const publicInputValues = [37];
      const verificationResult = await circuitProof.verifyProof(circuit, proof, publicInputValues);
      
      expect(verificationResult.verified).toBe(true);
      expect(verificationResult).not.toHaveProperty('inputs');
      expect(verificationResult).not.toHaveProperty('privateInputs');
    });
    
    test('Should reject circuit proof with invalid inputs', async () => {
      const circuit = {
        gates: [
          { type: 'mul', inputs: [0, 1], output: 3 },
          { type: 'add', inputs: [3, 2], output: 4 }
        ],
        publicInputs: [4],
        privateInputs: [0, 1, 2]
      };
      const inputs = [5, 6, 7, 30, 40];
      
      const circuitProof = new CircuitProof();
      const proof = await circuitProof.generateProof(circuit, inputs);
      const publicInputValues = [40];
      const verificationResult = await circuitProof.verifyProof(circuit, proof, publicInputValues);
      
      expect(verificationResult.verified).toBe(false);
    });
    
    test('Should prove complex circuit with multiple constraints', async () => {
      const circuit = {
        gates: [
          { type: 'add', inputs: [0, 1], output: 4 },
          { type: 'mul', inputs: [2, 3], output: 5 },
          { type: 'mul', inputs: [4, 5], output: 6 }
        ],
        publicInputs: [6],
        privateInputs: [0, 1, 2, 3]
      };
      const inputs = [10, 20, 5, 6, 30, 30, 900];
      
      const circuitProof = new CircuitProof();
      const proof = await circuitProof.generateProof(circuit, inputs);
      const publicInputValues = [900];
      const verificationResult = await circuitProof.verifyProof(circuit, proof, publicInputValues);
      
      expect(verificationResult.verified).toBe(true);
    });
  });
  
  ### ZKP Aggregator Tests
  describe('ZKP Aggregator Tests', () => {
    test('Should aggregate multiple ZKP proofs', async () => {
      const rangeProof = new RangeProof();
      const setProof = new SetMembershipProof();
      const ageProof = await rangeProof.generateProof(35, 18, 65);
      const allowedCodes = new Set([1001, 1002, 1003, 1004, 1005]);
      const codeProof = await setProof.generateProof(1003, allowedCodes);
      
      const aggregator = new ZKPAggregator();
      const aggregatedProof = await aggregator.aggregateProofs([
        { type: 'range', proof: ageProof, params: { min: 18, max: 65 } },
        { type: 'set', proof: codeProof, params: { set: allowedCodes } }
      ]);
      const verificationResult = await aggregator.verifyAggregatedProof(aggregatedProof);
      
      expect(verificationResult.verified).toBe(true);
      expect(verificationResult.results.length).toBe(2);
      expect(verificationResult.results[0].verified).toBe(true);
      expect(verificationResult.results[1].verified).toBe(true);
    });
    
    test('Should fail aggregated proof if any component fails', async () => {
      const rangeProof = new RangeProof();
      const setProof = new SetMembershipProof();
      const ageProof = await rangeProof.generateProof(35, 18, 65);
      const allowedCodes = new Set([1001, 1002, 1003, 1004, 1005]);
      const invalidCodeProof = await setProof.generateProof(2000, allowedCodes);
      
      const aggregator = new ZKPAggregator();
      const aggregatedProof = await aggregator.aggregateProofs([
        { type: 'range', proof: ageProof, params: { min: 18, max: 65 } },
        { type: 'set', proof: invalidCodeProof, params: { set: allowedCodes } }
      ]);
      const verificationResult = await aggregator.verifyAggregatedProof(aggregatedProof);
      
      expect(verificationResult.verified).toBe(false);
      expect(verificationResult.results.length).toBe(2);
      expect(verificationResult.results[0].verified).toBe(true);
      expect(verificationResult.results[1].verified).toBe(false);
    });
    
    test('Should support recursive proof composition', async () => {
      const aggregator = new ZKPAggregator();
      const rangeProof = new RangeProof();
      const setProof = new SetMembershipProof();
      const ageProof = await rangeProof.generateProof(35, 18, 65);
      const incomeProof = await rangeProof.generateProof(75000, 0, 100000);
      
      const level1Proof = await aggregator.aggregateProofs([
        { type: 'range', proof: ageProof, params: { min: 18, max: 65 } },
        { type: 'range', proof: incomeProof, params: { min: 0, max: 100000 } }
      ]);
      
      const allowedRegions = new Set([1, 2, 3, 4, 5]);
      const regionProof = await setProof.generateProof(3, allowedRegions);
      const level2Proof = await aggregator.aggregateProofs([
        { type: 'aggregate', proof: level1Proof },
        { type: 'set', proof: regionProof, params: { set: allowedRegions } }
      ]);
      
      const verificationResult = await aggregator.verifyAggregatedProof(level2Proof);
      
      expect(verificationResult.verified).toBe(true);
      expect(verificationResult.results.length).toBe(2);
      expect(verificationResult.results[0].verified).toBe(true);
      expect(verificationResult.results[0].results.length).toBe(2);
      expect(verificationResult.results[1].verified).toBe(true);
    });
  });
  
  ### Integration with Privacy Layer
  describe('Integration with Privacy Layer', () => {
    test('Should integrate with PrivacyLayer for data authentication', async () => {
      const rawData = { age: 35, income: 75000, region: 3, medicalCode: 1003 };
      const encryptionKey = crypto.randomBytes(32).toString('hex');
      const serializedData = JSON.stringify(rawData);
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey, 'hex'), iv);
      let encryptedData = cipher.update(serializedData, 'utf8', 'hex');
      encryptedData += cipher.final('hex');
      const dataHash = crypto.createHash('sha256').update(serializedData).digest('hex');
      
      const zkpRequest = {
        dataHash,
        proofs: [
          { type: 'range', attribute: 'age', min: 18, max: 65 },
          { type: 'range', attribute: 'income', min: 0, max: 100000 },
          { type: 'set', attribute: 'region', set: [1, 2, 3, 4, 5] },
          { type: 'set', attribute: 'medicalCode', set: [1001, 1002, 1003, 1004, 1005] }
        ]
      };
      
      const proofResult = await PrivacyLayer.generateZKProofs(zkpRequest, encryptedData, iv, encryptionKey);
      const verificationResult = await PrivacyLayer.verifyZKProofs(proofResult.proofs);
      
      expect(verificationResult.verified).toBe(true);
      expect(verificationResult.dataHash).toBe(dataHash);
      expect(verificationResult).not.toHaveProperty('rawData');
      expect(verificationResult).not.toHaveProperty('encryptedData');
    });
    
    test('Should support ZKP-based data queries', async () => {
      const dataset = [
        { id: 1, age: 25, income: 50000, region: 1, healthScore: 85 },
        { id: 2, age: 40, income: 80000, region: 2, healthScore: 90 },
        { id: 3, age: 35, income: 65000, region: 3, healthScore: 75 },
        { id: 4, age: 55, income: 120000, region: 2, healthScore: 60 },
        { id: 5, age: 30, income: 45000, region: 4, healthScore: 95 }
      ];
      const encryptedDataset = dataset.map(record => ({
        id: record.id,
        encryptedData: `encrypted-${record.id}`,
        dataHash: `hash-${record.id}`
      }));
      
      const query = {
        conditions: [
          { type: 'range', attribute: 'age', min: 30, max: 50 },
          { type: 'range', attribute: 'income', max: 100000 }
        ],
        returnAttributes: ['id', 'region']
      };
      
      const queryResult = await PrivacyLayer.executeZKPQuery(query, encryptedDataset, 'simulation-key');
      
      expect(queryResult.matchingRecords.length).toBe(3);
      queryResult.matchingRecords.forEach(record => {
        expect(record).toHaveProperty('id');
        expect(record).toHaveProperty('region');
        expect(record).not.toHaveProperty('age');
        expect(record).not.toHaveProperty('income');
        expect(record).not.toHaveProperty('healthScore');
      });
      
      const verificationResult = await PrivacyLayer.verifyZKPQueryResult(queryResult.proof, query);
      expect(verificationResult.verified).toBe(true);
    });
  });
  
  ### Blockchain Integration Tests
  describe('Blockchain Integration Tests', () => {
    test('Should register and verify ZKP on blockchain', async () => {
      const rangeProof = new RangeProof();
      const secretValue = 42;
      const proof = await rangeProof.generateProof(secretValue, 0, 100);
      
      const proofId = await DataVault.registerZKProof(proof, {
        type: 'range',
        params: { min: 0, max: 100 },
        dataHash: 'sample-data-hash-123'
      });
      
      expect(proofId).toBeDefined();
      const verificationResult = await DataVault.verifyZKProof(proofId);
      
      expect(verificationResult.verified).toBe(true);
      expect(verificationResult.dataHash).toBe('sample-data-hash-123');
      expect(verificationResult.attestation).toBeDefined();
      expect(verificationResult.blockNumber).toBeDefined();
      expect(verificationResult.timestamp).toBeDefined();
    });
    
    test('Should support ZKP-based access control on blockchain', async () => {
      const accessPolicy = {
        dataId: 'protected-dataset-456',
        requirements: [
          { type: 'range', attribute: 'age', min: 18, max: 65 },
          { type: 'credential', attribute: 'researcherId', issuer: 'trusted-institution' }
        ]
      };
      
      await DataVault.registerAccessPolicy(accessPolicy);
      const ageProof = await new RangeProof().generateProof(35, 18, 65);
      const credentialProof = { 
        type: 'credential', 
        credential: { attribute: 'researcherId', value: 'researcher-789', issuer: 'trusted-institution' }, 
        proof: 'simulated-credential-proof' 
      };
      
      const accessRequest = {
        dataId: 'protected-dataset-456',
        requesterId: 'researcher-789',
        proofs: [
          { type: 'range', proof: ageProof, params: { min: 18, max: 65 } },
          { type: 'credential', proof: credentialProof.proof }
        ]
      };
      
      const accessResult = await DataVault.requestZKPAccess(accessRequest);
      
      expect(accessResult.granted).toBe(true);
      expect(accessResult.accessToken).toBeDefined();
      
      const invalidAgeProof = await new RangeProof().generateProof(16, 18, 65);
      const invalidAccessRequest = {
        dataId: 'protected-dataset-456',
        requesterId: 'researcher-789',
        proofs: [
          { type: 'range', proof: invalidAgeProof, params: { min: 18, max: 65 } },
          { type: 'credential', proof: credentialProof.proof }
        ]
      };
      
      const invalidAccessResult = await DataVault.requestZKPAccess(invalidAccessRequest);
      
      expect(invalidAccessResult.granted).toBe(false);
      expect(invalidAccessResult.accessToken).toBeUndefined();
      expect(invalidAccessResult.reason).toBeDefined();
    });
  });
  
  ### Performance and Scalability Tests
  describe('Performance and Scalability Tests', () => {
    test('Should handle large set membership proofs', async () => {
      const largeSet = randomSet(1000, 1, 10000);
      const secretValue = Array.from(largeSet)[randomInt(0, largeSet.size)];
      
      const setProof = new SetMembershipProof();
      const startTime = Date.now();
      const proof = await setProof.generateProof(secretValue, largeSet);
      const verificationResult = await setProof.verifyProof(proof, largeSet);
      const duration = Date.now() - startTime;
      
      expect(verificationResult.verified).toBe(true);
      expect(duration).toBeLessThan(5000);
      console.log(`Large set proof (size ${largeSet.size}) took ${duration}ms`);
    });
    
    test('Should scale with circuit complexity', async () => {
      const circuitSizes = [5, 10, 20];
      const timings = [];
      
      for (const size of circuitSizes) {
        const circuit = generateRandomCircuit(size);
        const inputs = generateValidInputs(circuit);
        const circuitProof = new CircuitProof();
        
        const startTime = Date.now();
        const proof = await circuitProof.generateProof(circuit, inputs);
        const publicInputIndices = circuit.publicInputs || [];
        const publicInputValues = publicInputIndices.map(idx => inputs[idx]);
        const verificationResult = await circuitProof.verifyProof(circuit, proof, publicInputValues);
        const duration = Date.now() - startTime;
        
        expect(verificationResult.verified).toBe(true);
        timings.push({ size, duration });
      }
      
      console.log('Circuit complexity scaling:');
      timings.forEach(timing => console.log(`Circuit size ${timing.size}: ${timing.duration}ms`));
      
      if (timings.length >= 3) {
        const scalingRatio = timings[2].duration / timings[0].duration;
        const sizeRatio = timings[2].size / timings[0].size;
        expect(scalingRatio).toBeLessThan(sizeRatio * sizeRatio);
      }
    });
    
    test('Should optimize proof size for bandwidth efficiency', async () => {
      const rangeProof = new RangeProof();
      const secretValue = 42;
      
      const standardProof = await rangeProof.generateProof(secretValue, 0, 100);
      const optimizedProof = await rangeProof.generateOptimizedProof(secretValue, 0, 100);
      const standardResult = await rangeProof.verifyProof(standardProof, 0, 100);
      const optimizedResult = await rangeProof.verifyOptimizedProof(optimizedProof, 0, 100);
      
      expect(standardResult.verified).toBe(true);
      expect(optimizedResult.verified).toBe(true);
      
      const standardSize = JSON.stringify(standardProof).length;
      const optimizedSize = JSON.stringify(optimizedProof).length;
      expect(optimizedSize).toBeLessThan(standardSize);
      
      const reduction = ((standardSize - optimizedSize) / standardSize) * 100;
      console.log(`Proof size reduction: ${reduction.toFixed(2)}% (${standardSize} -> ${optimizedSize} bytes)`);
      expect(reduction).toBeGreaterThan(20);
    });
  });
  
  ### Security and Edge Case Tests
  describe('Security and Edge Case Tests', () => {
    test('Should be resistant to malleability attacks', async () => {
      const rangeProof = new RangeProof();
      const secretValue = 42;
      const proof = await rangeProof.generateProof(secretValue, 0, 100);
      
      const malleatedProof = JSON.parse(JSON.stringify(proof));
      if (malleatedProof.nonce) malleatedProof.nonce = 'modified-' + malleatedProof.nonce;
      else malleatedProof.extraField = 'malicious-data';
      
      const originalResult = await rangeProof.verifyProof(proof, 0, 100);
      const malleatedResult = await rangeProof.verifyProof(malleatedProof, 0, 100);
      
      expect(originalResult.verified).toBe(true);
      expect(malleatedResult.verified).toBe(false);
    });
    
    test('Should handle edge cases in range proofs', async () => {
      const rangeProof = new RangeProof();
      
      const lowerBoundProof = await rangeProof.generateProof(0, 0, 100);
      const upperBoundProof = await rangeProof.generateProof(100, 0, 100);
      expect((await rangeProof.verifyProof(lowerBoundProof, 0, 100)).verified).toBe(true);
      expect((await rangeProof.verifyProof(upperBoundProof, 0, 100)).verified).toBe(true);
      
      const exactValueProof = await rangeProof.generateProof(42, 42, 42);
      expect((await rangeProof.verifyProof(exactValueProof, 42, 42)).verified).toBe(true);
      
      const largeValueProof = await rangeProof.generateProof(
        Number.MAX_SAFE_INTEGER - 1000,
        Number.MAX_SAFE_INTEGER - 10000,
        Number.MAX_SAFE_INTEGER
      );
      expect((await rangeProof.verifyProof(
        largeValueProof,
        Number.MAX_SAFE_INTEGER - 10000,
        Number.MAX_SAFE_INTEGER
      )).verified).toBe(true);
      
      await expect(rangeProof.generateProof(50, 100, 0)).rejects.toThrow(/invalid range/i);
    });
    
    test('Should protect against timing attacks', async () => {
      const setProof = new SetMembershipProof();
      const allowedSet = new Set([10, 20, 30, 40, 50]);
      const validValue = 30;
      const invalidValue = 60;
      
      const validProof = await setProof.generateProof(validValue, allowedSet);
      const invalidProof = await setProof.generateProof(invalidValue, allowedSet);
      
      const times = { valid: [], invalid: [] };
      const iterations = 50;
      
      for (let i = 0; i < iterations; i++) {
        const validStart = process.hrtime.bigint();
        await setProof.verifyProof(validProof, allowedSet);
        times.valid.push(Number(process.hrtime.bigint() - validStart));
        
        const invalidStart = process.hrtime.bigint();
        await setProof.verifyProof(invalidProof, allowedSet);
        times.invalid.push(Number(process.hrtime.bigint() - invalidStart));
      }
      
      const validAvg = times.valid.reduce((a, b) => a + b, 0) / times.valid.length;
      const invalidAvg = times.invalid.reduce((a, b) => a + b, 0) / times.invalid.length;
      const timingRatio = Math.max(validAvg, invalidAvg) / Math.min(validAvg, invalidAvg);
      
      expect(timingRatio).toBeLessThan(1.2);
      expect((await setProof.verifyProof(validProof, allowedSet)).verified).toBe(true);
      expect((await setProof.verifyProof(invalidProof, allowedSet)).verified).toBe(false);
    });
  });
});

/**
 * Helper function to generate a random circuit for testing
 * @param {number} size - Number of gates in the circuit
 * @returns {Object} A circuit definition
 */
function generateRandomCircuit(size) {
  const numWires = size * 2;
  const gates = [];
  const gateTypes = ['add', 'mul', 'sub'];
  
  for (let i = 0; i < size; i++) {
    const type = gateTypes[Math.floor(Math.random() * gateTypes.length)];
    const input1 = Math.floor(Math.random() * Math.max(1, i));
    const input2 = Math.floor(Math.random() * Math.max(1, i));
    const output = i + size;
    
    gates.push({ type, inputs: [input1, input2], output });
  }
  
  const privateInputs = Array.from({ length: Math.floor(size / 2) }, (_, i) => i);
  const publicInputs = [size * 2 - 1];
  
  return { gates, privateInputs, publicInputs };
}

/**
 * Helper function to generate valid inputs for a circuit
 * @param {Object} circuit - Circuit definition
 * @returns {Array<number>} Valid inputs for the circuit
 */
function generateValidInputs(circuit) {
  const numWires = Math.max(...circuit.gates.map(gate => Math.max(...gate.inputs, gate.output))) + 1;
  const inputs = Array(numWires).fill(0);
  
  circuit.privateInputs.forEach(idx => {
    inputs[idx] = randomInt(1, 10);
  });
  
  for (const gate of circuit.gates) {
    const input1 = inputs[gate.inputs[0]];
    const input2 = inputs[gate.inputs[1]];
    switch (gate.type) {
      case 'add': inputs[gate.output] = input1 + input2; break;
      case 'mul': inputs[gate.output] = input1 * input2; break;
      case 'sub': inputs[gate.output] = input1 - input2; break;
    }
  }
  
  return inputs;
}
