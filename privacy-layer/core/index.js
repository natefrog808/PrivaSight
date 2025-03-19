/**
 * PrivaSight Privacy Layer - Main Entry Point
 * 
 * This file serves as the main entry point for the PrivaSight privacy layer.
 * It initializes and integrates all privacy components, including ZKP verification,
 * SMPC orchestration, and privacy-preserving analytics, with blockchain integration.
 */

// Core components
const PrivacyLayer = require('./PrivacyLayer');
const ZKPAccessVerifier = require('./ZKPAccessVerifier');
const SMPCOrchestrator = require('./SMPCOrchestrator');

// ZKP components
const { prover, verifier } = require('../zkp/proofs');
const { generateHash } = require('../zkp/utils/hash');
const { MerkleTree } = require('../zkp/utils/merkle');

// SMPC components
const SMPCNode = require('../smpc/node');
const { SecretSharing } = require('../smpc/secret-sharing');
const Coordinator = require('../smpc/coordinator');
const { AverageProtocol, StatisticalProtocol } = require('../smpc/protocols');

// Analytics components
const { FederatedLearning } = require('../analytics/federated-learning');
const { DifferentialPrivacy } = require('../analytics/differential-privacy');
const { RegressionModel, ClusteringModel } = require('../analytics/models');

// Web3 and blockchain integration
const Web3 = require('web3');
const ethers = require('ethers');
const contractABIs = require('../../contracts/interfaces');

// Configuration and utilities
const config = require('../../config/privacy-layer.config');
const logger = require('../../utils/logger')('privacy-layer');
const { EncryptionService } = require('../../utils/encryption');

/**
 * Validates the configuration object to ensure all required parameters are present
 * @throws {Error} If required configuration parameters are missing or invalid
 */
function validateConfig() {
  const requiredConfig = [
    'web3.providerUrl',
    'contracts.dataVaultNFTAddress',
    'contracts.privaTokenAddress',
    'contracts.marketplaceAddress',
    'contracts.verifierRegistryAddress',
    'smpc.threshold',
    'smpc.totalShares',
    'smpc.nodeAddresses',
    'smpc.coordinationTimeout',
    'analytics.federatedLearning.aggregationStrategy',
    'analytics.federatedLearning.minParticipants',
    'analytics.differentialPrivacy.epsilon',
    'analytics.differentialPrivacy.delta',
    'encryption.keySize',
    'encryption.algorithm'
  ];

  for (const path of requiredConfig) {
    const keys = path.split('.');
    let current = config;
    for (const key of keys) {
      if (!current[key]) {
        throw new Error(`Missing required configuration: ${path}`);
      }
      current = current[key];
    }
  }

  // Additional validation for SMPC parameters
  if (config.smpc.threshold < 1 || config.smpc.threshold > config.smpc.totalShares) {
    throw new Error('Invalid SMPC threshold: must be between 1 and totalShares');
  }

  // Ensure nodeAddresses is an array
  if (!Array.isArray(config.smpc.nodeAddresses) || config.smpc.nodeAddresses.length === 0) {
    throw new Error('smpc.nodeAddresses must be a non-empty array');
  }

  logger.info('Configuration validated successfully');
}

/**
 * Initialize the Web3 provider based on configuration
 * @returns {Web3} Configured Web3 instance
 * @throws {Error} If Web3 provider initialization fails
 */
function initializeWeb3() {
  let provider;

  try {
    if (config.web3.useWsProvider) {
      provider = new Web3.providers.WebsocketProvider(config.web3.providerUrl);
    } else {
      provider = new Web3.providers.HttpProvider(config.web3.providerUrl);
    }

    const web3 = new Web3(provider);
    logger.info('Web3 provider initialized');
    return web3;
  } catch (error) {
    logger.error('Failed to initialize Web3 provider:', error);
    throw new Error(`Web3 initialization failed: ${error.message}`);
  }
}

/**
 * Load and initialize smart contract instances
 * @param {Web3} web3 - Web3 instance
 * @returns {Object} Object containing contract instances
 * @throws {Error} If contract initialization fails or addresses are invalid
 */
function initializeContracts(web3) {
  const contracts = {};

  // Validate contract addresses
  const isValidAddress = (address) => web3.utils.isAddress(address);
  const contractConfigs = {
    dataVaultNFT: config.contracts.dataVaultNFTAddress,
    privaToken: config.contracts.privaTokenAddress,
    marketplace: config.contracts.marketplaceAddress,
    verifierRegistry: config.contracts.verifierRegistryAddress
  };

  for (const [name, address] of Object.entries(contractConfigs)) {
    if (!isValidAddress(address)) {
      throw new Error(`Invalid contract address for ${name}: ${address}`);
    }
  }

  try {
    contracts.dataVaultNFT = new web3.eth.Contract(
      contractABIs.IDataVaultNFT,
      config.contracts.dataVaultNFTAddress
    );

    contracts.privaToken = new web3.eth.Contract(
      contractABIs.IPrivaToken,
      config.contracts.privaTokenAddress
    );

    contracts.marketplace = new web3.eth.Contract(
      contractABIs.IMarketplace,
      config.contracts.marketplaceAddress
    );

    contracts.verifierRegistry = new web3.eth.Contract(
      contractABIs.IVerifierRegistry,
      config.contracts.verifierRegistryAddress
    );

    logger.info('Smart contracts initialized');
    return contracts;
  } catch (error) {
    logger.error('Failed to initialize contracts:', error);
    throw new Error(`Contract initialization failed: ${error.message}`);
  }
}

/**
 * Initialize the ZKP components
 * @returns {Object} Initialized ZKP components
 * @throws {Error} If ZKP initialization fails
 */
function initializeZKP() {
  try {
    const zkpVerifier = new ZKPAccessVerifier({
      prover,
      verifier,
      hashFunction: generateHash
    });

    logger.info('ZKP components initialized');
    return {
      verifier: zkpVerifier,
      merkleTree: MerkleTree
    };
  } catch (error) {
    logger.error('Failed to initialize ZKP components:', error);
    throw new Error(`ZKP initialization failed: ${error.message}`);
  }
}

/**
 * Initialize SMPC components
 * @returns {Object} Initialized SMPC components
 * @throws {Error} If SMPC initialization fails
 */
function initializeSMPC() {
  try {
    const secretSharing = new SecretSharing({
      threshold: config.smpc.threshold,
      totalShares: config.smpc.totalShares
    });

    const coordinator = new Coordinator({
      nodeAddresses: config.smpc.nodeAddresses,
      timeout: config.smpc.coordinationTimeout
    });

    const smpcOrchestrator = new SMPCOrchestrator({
      secretSharing,
      coordinator,
      protocols: {
        average: new AverageProtocol(),
        statistical: new StatisticalProtocol()
      }
    });

    logger.info('SMPC components initialized');
    return {
      orchestrator: smpcOrchestrator,
      secretSharing,
      coordinator
    };
  } catch (error) {
    logger.error('Failed to initialize SMPC components:', error);
    throw new Error(`SMPC initialization failed: ${error.message}`);
  }
}

/**
 * Initialize analytics components
 * @returns {Object} Initialized analytics components
 * @throws {Error} If analytics initialization fails
 */
function initializeAnalytics() {
  try {
    const federatedLearning = new FederatedLearning({
      aggregationStrategy: config.analytics.federatedLearning.aggregationStrategy,
      minParticipants: config.analytics.federatedLearning.minParticipants
    });

    const differentialPrivacy = new DifferentialPrivacy({
      epsilon: config.analytics.differentialPrivacy.epsilon,
      delta: config.analytics.differentialPrivacy.delta
    });

    const models = {
      regression: new RegressionModel(),
      clustering: new ClusteringModel()
    };

    logger.info('Analytics components initialized');
    return {
      federatedLearning,
      differentialPrivacy,
      models
    };
  } catch (error) {
    logger.error('Failed to initialize analytics components:', error);
    throw new Error(`Analytics initialization failed: ${error.message}`);
  }
}

/**
 * Initialize event listeners for blockchain events
 * @param {Object} contracts - Contract instances
 * @param {PrivacyLayer} privacyLayer - PrivacyLayer instance
 * @throws {Error} If event listener setup fails
 */
function setupEventListeners(contracts, privacyLayer) {
  try {
    // New DataVault creation (NFT minting)
    contracts.dataVaultNFT.events.Transfer({
      filter: { from: '0x0000000000000000000000000000000000000000' }
    })
      .on('data', async (event) => {
        const tokenId = event.returnValues.tokenId;
        logger.info(`New DataVault created: ${tokenId}`);
        try {
          await privacyLayer.registerDataVault(tokenId);
        } catch (err) {
          logger.error(`Failed to register DataVault ${tokenId}:`, err);
        }
      })
      .on('error', (error) => {
        logger.error('Error in DataVault Transfer event listener:', error);
      });

    // Access request events
    contracts.marketplace.events.AccessRequested()
      .on('data', async (event) => {
        const { listingId, researcher, purpose } = event.returnValues;
        logger.info(`New access request for listing ${listingId} from ${researcher}`);
        try {
          await privacyLayer.processAccessRequest(listingId, researcher, purpose);
        } catch (err) {
          logger.error(`Failed to process access request ${listingId}:`, err);
        }
      })
      .on('error', (error) => {
        logger.error('Error in AccessRequested event listener:', error);
      });

    // Access approval events
    contracts.marketplace.events.AccessApproved()
      .on('data', async (event) => {
        const { listingId, researcher } = event.returnValues;
        logger.info(`Access approved for listing ${listingId} to researcher ${researcher}`);
        try {
          await privacyLayer.setupSecureAccess(listingId, researcher);
        } catch (err) {
          logger.error(`Failed to setup secure access for ${listingId}:`, err);
        }
      })
      .on('error', (error) => {
        logger.error('Error in AccessApproved event listener:', error);
      });

    // Computation request events
    contracts.verifierRegistry.events.ComputationRequested()
      .on('data', async (event) => {
        const { requestId, researcher, dataVaultIds, computationType } = event.returnValues;
        logger.info(`New computation request ${requestId} from ${researcher}`);
        try {
          await privacyLayer.orchestrateComputation(requestId, researcher, dataVaultIds, computationType);
        } catch (err) {
          logger.error(`Failed to orchestrate computation ${requestId}:`, err);
        }
      })
      .on('error', (error) => {
        logger.error('Error in ComputationRequested event listener:', error);
      });

    logger.info('Blockchain event listeners initialized');
  } catch (error) {
    logger.error('Failed to setup event listeners:', error);
    throw new Error(`Event listener setup failed: ${error.message}`);
  }
}

/**
 * Creates and initializes the complete Privacy Layer
 * @returns {PrivacyLayer} Initialized Privacy Layer instance
 * @throws {Error} If Privacy Layer initialization fails
 */
function createPrivacyLayer() {
  try {
    // Validate configuration first
    validateConfig();

    // Initialize Web3 and contracts
    const web3 = initializeWeb3();
    const contracts = initializeContracts(web3);

    // Initialize component layers
    const zkp = initializeZKP();
    const smpc = initializeSMPC();
    const analytics = initializeAnalytics();

    // Create encryption service
    const encryptionService = new EncryptionService({
      keySize: config.encryption.keySize,
      algorithm: config.encryption.algorithm
    });

    // Create the main Privacy Layer instance
    const privacyLayer = new PrivacyLayer({
      contracts,
      zkpVerifier: zkp.verifier,
      smpcOrchestrator: smpc.orchestrator,
      encryptionService,
      federatedLearning: analytics.federatedLearning,
      differentialPrivacy: analytics.differentialPrivacy,
      config
    });

    // Set up event listeners
    setupEventListeners(contracts, privacyLayer);

    logger.info('PrivaSight Privacy Layer successfully initialized');
    return privacyLayer;
  } catch (error) {
    logger.error('Failed to initialize Privacy Layer:', error);
    throw new Error(`Privacy Layer initialization failed: ${error.message}`);
  }
}

// Export factory function and component classes
module.exports = {
  createPrivacyLayer,
  PrivacyLayer,
  ZKPAccessVerifier,
  SMPCOrchestrator,
  // Export additional components for direct access
  zkp: {
    prover,
    verifier,
    MerkleTree,
    generateHash
  },
  smpc: {
    SecretSharing,
    Coordinator,
    protocols: {
      AverageProtocol,
      StatisticalProtocol
    }
  },
  analytics: {
    FederatedLearning,
    DifferentialPrivacy,
    models: {
      RegressionModel,
      ClusteringModel
    }
  }
};
