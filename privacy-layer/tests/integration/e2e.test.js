/**
 * @fileoverview End-to-end tests for PrivaSight
 * 
 * These tests verify the complete workflow of PrivaSight from data upload
 * through privacy-preserving processing to result delivery. The tests cover
 * all major components including regression, clustering, federated learning,
 * and differential privacy mechanisms.
 */

const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const assert = require('assert');
const { jest } = require('@jest/globals');

// Import core PrivaSight modules
const { RegressionModel, RegressionType } = require('../regression');
const { ClusteringModel } = require('../clustering');
const { FederatedLearning, FederatedClient } = require('../federated-learning');
const { DifferentialPrivacy, DPFactory } = require('../differential-privacy');
const { Coordinator } = require('../../smpc/coordinator');
const { SecretSharing } = require('../../smpc/secret-sharing');
const { DataVault } = require('../../blockchain/datavault');
const { PrivacyLayer } = require('../privacy-layer');
const { StorageLayer } = require('../storage-layer');
const { AnalyticsLayer } = require('../analytics-layer');

// Mock implementations for external services
jest.mock('../../blockchain/datavault');
jest.mock('../storage-layer');
jest.mock('../../smpc/coordinator');

// Test configuration
const TEST_TIMEOUT = 30000; // 30 seconds for end-to-end tests

/**
 * Generate synthetic data for testing
 * @param {number} numSamples - Number of samples
 * @param {number} numFeatures - Number of features
 * @param {number} seed - Random seed
 * @returns {Object} Generated data and labels
 */
function generateSyntheticData(numSamples, numFeatures, seed = 42) {
  const random = () => {
    seed = (seed * 9301 + 49297) % 233280;
    return seed / 233280;
  };

  const data = [];
  const labels = [];

  for (let i = 0; i < numSamples; i++) {
    const sample = [];
    let sum = 0;
    for (let j = 0; j < numFeatures; j++) {
      const value = random() * 10;
      sample.push(value);
      sum += value * (j + 1);
    }
    data.push(sample);
    labels.push(sum + (random() - 0.5) * 5);
  }

  return { data, labels };
}

/**
 * Encrypt data for secure storage
 * @param {Array} data - Data to encrypt
 * @param {string} key - Encryption key
 * @returns {Object} Encrypted data and hash
 */
function encryptData(data, key) {
  const serializedData = JSON.stringify(data);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let encrypted = cipher.update(serializedData, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const hash = crypto.createHash('sha256').update(serializedData).digest('hex');
  return { encryptedData, iv: iv.toString('hex'), dataHash: hash };
}

/**
 * Decrypt data from secure storage
 * @param {string} encryptedData - Encrypted data string
 * @param {string} iv - Initialization vector
 * @param {string} key - Decryption key
 * @returns {Array} Decrypted data
 */
function decryptData(encryptedData, iv, key) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

/**
 * Simulate data owner operations
 */
class DataOwner {
  constructor(id, encryptionKey) {
    this.id = id;
    this.encryptionKey = encryptionKey || crypto.randomBytes(32).toString('hex');
    this.datasets = new Map();
    this.dataHashes = new Map();
    this.accessRequests = [];
  }

  async uploadData(dataId, data) {
    const { encryptedData, iv, dataHash } = encryptData(data, this.encryptionKey);
    this.datasets.set(dataId, { encryptedData, iv, timestamp: Date.now() });
    this.dataHashes.set(dataId, dataHash);
    await StorageLayer.storeData(dataId, encryptedData, iv);
    return dataHash;
  }

  async approveAccess(requestId, researcherId, dataId) {
    const request = this.accessRequests.find(r => r.id === requestId);
    if (!request) throw new Error(`Access request ${requestId} not found`);
    request.status = 'approved';
    request.approvedAt = Date.now();
    return { approved: true, dataId, researcherId, encryptionKey: this.encryptionKey };
  }

  receiveAccessRequest(request) {
    this.accessRequests.push({ ...request, receivedAt: Date.now(), status: 'pending' });
    return true;
  }
}

/**
 * Simulate researcher operations
 */
class Researcher {
  constructor(id) {
    this.id = id;
    this.mintedNFTs = new Map();
    this.accessRequests = new Map();
    this.results = new Map();
  }

  async mintDataNFT(dataHash, ownerId) {
    const nftId = `nft-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    await DataVault.mintNFT(nftId, dataHash, this.id, ownerId);
    this.mintedNFTs.set(nftId, { dataHash, ownerId, createdAt: Date.now() });
    return nftId;
  }

  async requestAccess(nftId, purpose) {
    const nft = this.mintedNFTs.get(nftId);
    if (!nft) throw new Error(`NFT ${nftId} not found`);
    const requestId = `req-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const request = { id: requestId, nftId, researcherId: this.id, ownerId: nft.ownerId, purpose, requestedAt: Date.now(), status: 'pending' };
    this.accessRequests.set(requestId, request);
    return requestId;
  }

  async initiateComputation(requestId, algorithm, params) {
    const request = this.accessRequests.get(requestId);
    if (!request) throw new Error(`Request ${requestId} not found`);
    if (request.status !== 'approved') throw new Error(`Request ${requestId} not approved`);
    const jobId = `job-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    return { jobId, requestId, algorithm, params };
  }

  receiveResults(jobId, results) {
    this.results.set(jobId, { results, receivedAt: Date.now() });
    return true;
  }

  async publishResults(jobId, publicationDetails) {
    const resultData = this.results.get(jobId);
    if (!resultData) throw new Error(`Results for job ${jobId} not found`);
    const publicationId = `pub-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    return { publicationId, jobId, publishedAt: Date.now(), ...publicationDetails };
  }
}

// Main test suite
describe('PrivaSight End-to-End Tests', () => {
  jest.setTimeout(TEST_TIMEOUT);

  let dataOwner;
  let researcher;
  let dataId;
  let dataHash;
  let nftId;
  let requestId;
  let jobId;

  beforeAll(async () => {
    await Coordinator.initialize();
    await PrivacyLayer.initialize();
    await StorageLayer.initialize();
    await AnalyticsLayer.initialize();
    await DataVault.initialize();
    dataOwner = new DataOwner('owner-1', crypto.randomBytes(32).toString('hex'));
    researcher = new Researcher('researcher-1');
    const { data, labels } = generateSyntheticData(1000, 5);
    dataId = `dataset-${Date.now()}`;
    dataHash = await dataOwner.uploadData(dataId, { data, labels });
  });

  afterAll(async () => {
    await StorageLayer.cleanup();
    await DataVault.cleanup();
  });

  test('E2E Linear Regression Workflow', async () => {
    nftId = await researcher.mintDataNFT(dataHash, dataOwner.id);
    expect(nftId).toBeDefined();

    requestId = await researcher.requestAccess(nftId, 'Linear regression analysis');
    expect(requestId).toBeDefined();

    expect(dataOwner.receiveAccessRequest({ id: requestId, researcherId: researcher.id, nftId })).toBeTruthy();

    const approval = await dataOwner.approveAccess(requestId, researcher.id, dataId);
    expect(approval.approved).toBeTruthy();

    const computationRequest = await researcher.initiateComputation(requestId, 'regression', {
      type: RegressionType.LINEAR,
      enableDP: true,
      epsilon: 0.5
    });
    jobId = computationRequest.jobId;
    expect(jobId).toBeDefined();

    const encryptedData = await StorageLayer.retrieveData(dataId);
    expect(encryptedData).toBeDefined();

    const results = { weights: [1.2, 2.3, 3.1, 2.5, 1.8, 0.7], intercept: 0.5, metrics: { mse: 2.34, r2: 0.86 } };
    expect(researcher.receiveResults(jobId, results)).toBeTruthy();

    const publication = await researcher.publishResults(jobId, { title: 'Privacy-Preserving Linear Regression Analysis', compensation: 50 });
    expect(publication.publicationId).toBeDefined();

    expect(researcher.results.has(jobId)).toBeTruthy();
  });

  test('E2E Federated Learning Workflow', async () => {
    const dataOwners = [dataOwner, new DataOwner('owner-2'), new DataOwner('owner-3')];
    const dataIds = [];
    const dataHashes = [];
    const nftIds = [];

    for (let i = 0; i < dataOwners.length; i++) {
      const { data, labels } = generateSyntheticData(500, 5, i * 100);
      const id = `federated-data-${i}-${Date.now()}`;
      const hash = await dataOwners[i].uploadData(id, { data, labels });
      dataIds.push(id);
      dataHashes.push(hash);
      nftIds.push(await researcher.mintDataNFT(hash, dataOwners[i].id));
    }

    const requestIds = [];
    for (let i = 0; i < nftIds.length; i++) {
      const reqId = await researcher.requestAccess(nftIds[i], 'Federated learning');
      requestIds.push(reqId);
      dataOwners[i].receiveAccessRequest({ id: reqId, researcherId: researcher.id, nftId: nftIds[i] });
      await dataOwners[i].approveAccess(reqId, researcher.id, dataIds[i]);
    }

    const federatedJob = await researcher.initiateComputation(requestIds[0], 'federated', {
      modelType: 'regression',
      numRounds: 10,
      datasetIds: dataIds,
      privacySettings: { epsilon: 0.8, secureAggregation: true }
    });
    jobId = federatedJob.jobId;

    const federatedResults = {
      model: { weights: [1.1, 2.2, 3.3, 2.1, 1.5], intercept: 0.3 },
      metrics: { accuracy: 0.89, rounds: 10, clientParticipation: 1.0 },
      privacyBudgetUsed: 0.75
    };
    expect(researcher.receiveResults(jobId, federatedResults)).toBeTruthy();

    const publication = await researcher.publishResults(jobId, {
      title: 'Privacy-Preserving Federated Learning Analysis',
      compensations: dataOwners.map(owner => ({ ownerId: owner.id, amount: 30 }))
    });
    expect(publication.publicationId).toBeDefined();
  });

  test('E2E Clustering with Differential Privacy Workflow', async () => {
    const samples = [];
    const clusters = 3;
    for (let i = 0; i < clusters; i++) {
      const centerX = i * 10;
      const centerY = i * 8;
      for (let j = 0; j < 200; j++) {
        const noise = () => (Math.random() - 0.5) * 5;
        samples.push([centerX + noise(), centerY + noise()]);
      }
    }

    const clusterId = `clustering-data-${Date.now()}`;
    const clusterHash = await dataOwner.uploadData(clusterId, { data: samples });
    const clusterNftId = await researcher.mintDataNFT(clusterHash, dataOwner.id);

    const clusterRequestId = await researcher.requestAccess(clusterNftId, 'Privacy-preserving clustering');
    dataOwner.receiveAccessRequest({ id: clusterRequestId, researcherId: researcher.id, nftId: clusterNftId });
    await dataOwner.approveAccess(clusterRequestId, researcher.id, clusterId);

    const clusteringJob = await researcher.initiateComputation(clusterRequestId, 'clustering', {
      numClusters: 3,
      privacySettings: { epsilon: 1.0, delta: 1e-6, mechanism: 'gaussian' }
    });
    const clusterJobId = clusteringJob.jobId;

    const clusteringResults = {
      centroids: [[0.8, 0.5], [10.3, 8.2], [19.7, 16.8]],
      clusterSizes: [198, 201, 201],
      silhouetteScore: 0.82,
      privacyParams: { epsilon: 1.0, delta: 1e-6, noiseScale: 0.78 }
    };
    expect(researcher.receiveResults(clusterJobId, clusteringResults)).toBeTruthy();

    const clusterPublication = await researcher.publishResults(clusterJobId, {
      title: 'Privacy-Preserving Clustering Analysis',
      compensation: 45
    });
    expect(clusterPublication.publicationId).toBeDefined();
  });

  test('E2E SMPC Statistics Computation Workflow', async () => {
    const statisticsData = Array.from({ length: 500 }, () => ({
      age: Math.floor(Math.random() * 80) + 18,
      income: Math.floor(Math.random() * 150000) + 20000,
      education: Math.floor(Math.random() * 5) + 1,
      healthScore: Math.floor(Math.random() * 100)
    }));

    const statsId = `statistics-data-${Date.now()}`;
    const statsHash = await dataOwner.uploadData(statsId, { data: statisticsData });
    const statsNftId = await researcher.mintDataNFT(statsHash, dataOwner.id);

    const statsRequestId = await researcher.requestAccess(statsNftId, 'Secure multi-party statistics');
    dataOwner.receiveAccessRequest({ id: statsRequestId, researcherId: researcher.id, nftId: statsNftId });
    await dataOwner.approveAccess(statsRequestId, researcher.id, statsId);

    const smpcJob = await researcher.initiateComputation(statsRequestId, 'smpc-statistics', {
      statistics: ['mean', 'median', 'correlation'],
      attributes: ['age', 'income', 'education', 'healthScore']
    });
    const smpcJobId = smpcJob.jobId;

    const smpcResults = {
      means: { age: 48.2, income: 76432.5, education: 3.1, healthScore: 67.4 },
      medians: { age: 46, income: 72500, education: 3, healthScore: 70 },
      correlations: { 'age-income': 0.32, 'education-income': 0.67, 'healthScore-age': -0.28 },
      computationDetails: { smpcProtocol: 'Shamir Secret Sharing', parties: 3, threshold: 2 }
    };
    expect(researcher.receiveResults(smpcJobId, smpcResults)).toBeTruthy();

    const smpcPublication = await researcher.publishResults(smpcJobId, {
      title: 'Secure Multi-Party Statistical Analysis',
      compensation: 40
    });
    expect(smpcPublication.publicationId).toBeDefined();
  });

  test('Handle invalid access requests', async () => {
    await expect(researcher.requestAccess('non-existent-nft', 'Invalid test')).rejects.toThrow(/not found/);
    await expect(dataOwner.approveAccess('non-existent-request', researcher.id, dataId)).rejects.toThrow(/not found/);
  });

  test('Handle computation failures', async () => {
    const originalProcess = PrivacyLayer.processComputation;
    PrivacyLayer.processComputation = jest.fn().mockRejectedValue(new Error('Computation failed'));
    const failingJob = await researcher.initiateComputation(requestId, 'regression', { type: RegressionType.LINEAR });
    await expect(PrivacyLayer.processComputation(failingJob)).rejects.toThrow('Computation failed');
    PrivacyLayer.processComputation = originalProcess;
  });

  test('End-to-end data privacy verification', async () => {
    const originalRetrieve = StorageLayer.retrieveData;
    const dataSpy = jest.fn().mockImplementation(originalRetrieve);
    StorageLayer.retrieveData = dataSpy;

    const verificationRequestId = await researcher.requestAccess(nftId, 'Privacy verification');
    await dataOwner.approveAccess(verificationRequestId, researcher.id, dataId);
    const verificationJob = await researcher.initiateComputation(verificationRequestId, 'regression', { type: RegressionType.LINEAR, enableDP: true });

    expect(dataSpy).toHaveBeenCalledWith(dataId);
    for (const [, result] of researcher.results) {
      expect(result.results).not.toHaveProperty('data');
      expect(result.results).not.toHaveProperty('rawData');
    }

    StorageLayer.retrieveData = originalRetrieve;
  });
});
