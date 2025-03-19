/**
 * PrivaSight Privacy Layer
 * 
 * Core integration layer that coordinates all privacy-preserving components of the system.
 * Manages the interaction between blockchain contracts, ZKP verification, SMPC orchestration,
 * and privacy-preserving analytics.
 */

const EventEmitter = require('events');
const { v4: uuidv4 } = require('uuid');
const logger = require('../../utils/logger')('privacy-layer:core');

/**
 * Main Privacy Layer class that integrates all privacy components
 * @class PrivacyLayer
 * @extends EventEmitter
 */
class PrivacyLayer extends EventEmitter {
  /**
   * Create a new Privacy Layer instance
   * @param {Object} options - Configuration options
   * @param {Object} options.contracts - Blockchain contract instances
   * @param {Object} options.zkpVerifier - ZKP verification component
   * @param {Object} options.smpcOrchestrator - SMPC orchestration component
   * @param {Object} options.encryptionService - Encryption service
   * @param {Object} options.federatedLearning - Federated learning component
   * @param {Object} options.differentialPrivacy - Differential privacy component
   * @param {Object} options.config - Configuration settings
   */
  constructor({
    contracts,
    zkpVerifier,
    smpcOrchestrator,
    encryptionService,
    federatedLearning,
    differentialPrivacy,
    config
  }) {
    super();
    
    // Store components and configuration
    this.contracts = contracts;
    this.zkpVerifier = zkpVerifier;
    this.smpcOrchestrator = smpcOrchestrator;
    this.encryptionService = encryptionService;
    this.federatedLearning = federatedLearning;
    this.differentialPrivacy = differentialPrivacy;
    this.config = config;
    
    // Initialize internal state
    this.dataVaults = new Map(); // Map of dataVaultId => metadata
    this.accessRequests = new Map(); // Map of requestId => request metadata
    this.computations = new Map(); // Map of computationId => computation state
    this.accessProofs = new Map(); // Map of (listingId, researcher) => access proof
    
    // Bind methods to maintain context
    this.registerDataVault = this.registerDataVault.bind(this);
    this.processAccessRequest = this.processAccessRequest.bind(this);
    this.setupSecureAccess = this.setupSecureAccess.bind(this);
    this.revokeAccess = this.revokeAccess.bind(this); // Added revocation method
    this.orchestrateComputation = this.orchestrateComputation.bind(this);
    this.verifyAccessRights = this.verifyAccessRights.bind(this);
    this.executePrivateComputation = this.executePrivateComputation.bind(this);
    this.publishResults = this.publishResults.bind(this);
    
    logger.info('Privacy Layer initialized');
  }

  /**
   * Register a new data vault in the privacy layer
   * @param {string} dataVaultId - ID of the data vault
   * @returns {Promise<Object>} Vault metadata
   * @throws {Error} If registration fails or vault already exists
   */
  async registerDataVault(dataVaultId) {
    try {
      if (this.dataVaults.has(dataVaultId)) {
        throw new Error(`Data vault ${dataVaultId} already registered`);
      }
      
      logger.info(`Registering data vault ${dataVaultId}`);
      
      // Fetch data vault metadata from blockchain
      const vaultData = await this.contracts.dataVaultNFT.methods.getVaultMetadata(dataVaultId).call();
      
      // Generate encryption keys for the vault
      const encryptionKeys = await this.encryptionService.generateKeyPair();
      
      // Store vault metadata
      const vaultMetadata = {
        id: dataVaultId,
        owner: vaultData.owner,
        encryptionKeys,
        accessRules: vaultData.accessRules,
        dataHash: vaultData.dataHash,
        registeredAt: Date.now()
      };
      
      this.dataVaults.set(dataVaultId, vaultMetadata);
      
      // Emit event for downstream components
      this.emit('vault:registered', vaultMetadata);
      
      logger.info(`Data vault ${dataVaultId} registered successfully`);
      return vaultMetadata;
    } catch (error) {
      logger.error(`Failed to register data vault ${dataVaultId}:`, error);
      throw new Error(`Data vault registration failed: ${error.message}`);
    }
  }

  /**
   * Process an access request from a researcher
   * @param {string} listingId - ID of the marketplace listing
   * @param {string} researcher - Address of the researcher
   * @param {string} purpose - Purpose of the access request
   * @returns {Promise<Object>} Access request metadata
   * @throws {Error} If processing fails or researcher is not verified
   */
  async processAccessRequest(listingId, researcher, purpose) {
    try {
      logger.info(`Processing access request for listing ${listingId} from ${researcher}`);
      
      // Fetch listing from marketplace
      const listing = await this.contracts.marketplace.methods.getListing(listingId).call();
      const dataVaultId = listing.dataVaultId;
      
      // Check if data vault is registered; if not, register it
      if (!this.dataVaults.has(dataVaultId)) {
        await this.registerDataVault(dataVaultId);
      }
      
      // Verify researcher's credentials
      const isVerified = await this.contracts.marketplace.methods.isResearcherVerified(researcher).call();
      if (!isVerified) {
        throw new Error(`Researcher ${researcher} is not verified`);
      }
      
      // Generate a unique request ID
      const requestId = uuidv4();
      
      // Create access request metadata
      const requestMetadata = {
        id: requestId,
        listingId,
        dataVaultId,
        researcher,
        purpose,
        status: 'pending',
        requestedAt: Date.now()
      };
      
      this.accessRequests.set(requestId, requestMetadata);
      
      // Emit event for downstream components
      this.emit('access:requested', requestMetadata);
      
      logger.info(`Access request ${requestId} processed successfully`);
      return requestMetadata;
    } catch (error) {
      logger.error(`Failed to process access request for listing ${listingId}:`, error);
      throw new Error(`Access request processing failed: ${error.message}`);
    }
  }

  /**
   * Set up secure access for an approved request
   * @param {string} listingId - ID of the marketplace listing
   * @param {string} researcher - Address of the researcher
   * @returns {Promise<Object>} Access metadata
   * @throws {Error} If setup fails or vault is not registered
   */
  async setupSecureAccess(listingId, researcher) {
    try {
      logger.info(`Setting up secure access for listing ${listingId} and researcher ${researcher}`);
      
      // Fetch listing from marketplace
      const listing = await this.contracts.marketplace.methods.getListing(listingId).call();
      const dataVaultId = listing.dataVaultId;
      
      // Get data vault metadata
      const vaultMetadata = this.dataVaults.get(dataVaultId);
      if (!vaultMetadata) {
        throw new Error(`Data vault ${dataVaultId} not registered`);
      }
      
      // Generate ZKP access proof
      const accessProof = await this.zkpVerifier.generateAccessProof({
        dataVaultId,
        researcher,
        accessType: listing.accessType,
        timestamp: Date.now()
      });
      
      // Generate secure access key for the researcher
      const accessKey = await this.encryptionService.generateAccessKey(
        vaultMetadata.encryptionKeys.publicKey,
        { researcher, listingId, expiresAt: Date.now() + (86400000 * 30) } // 30 days expiry
      );
      
      // Store access proof with expiration
      const accessKeyId = `${listingId}-${researcher}`;
      this.accessProofs.set(accessKeyId, {
        proof: accessProof,
        accessKey,
        dataVaultId,
        listingId,
        researcher,
        createdAt: Date.now(),
        expiresAt: Date.now() + (86400000 * 30) // 30 days expiry
      });
      
      // Emit event for downstream components
      this.emit('access:granted', {
        dataVaultId,
        listingId,
        researcher,
        accessProof,
        accessKey
      });
      
      logger.info(`Secure access set up for listing ${listingId} and researcher ${researcher}`);
      
      return {
        dataVaultId,
        listingId,
        researcher,
        accessKey,
        proofId: accessProof.id
      };
    } catch (error) {
      logger.error(`Failed to set up secure access for listing ${listingId}:`, error);
      throw new Error(`Secure access setup failed: ${error.message}`);
    }
  }

  /**
   * Revoke access for a researcher to a listing
   * @param {string} listingId - ID of the marketplace listing
   * @param {string} researcher - Address of the researcher
   * @returns {Promise<void>}
   * @throws {Error} If revocation fails or access does not exist
   */
  async revokeAccess(listingId, researcher) {
    try {
      const accessKeyId = `${listingId}-${researcher}`;
      const accessData = this.accessProofs.get(accessKeyId);
      
      if (!accessData) {
        throw new Error(`No access found for listing ${listingId} and researcher ${researcher}`);
      }
      
      // Remove access proof
      this.accessProofs.delete(accessKeyId);
      
      // Emit event for downstream components
      this.emit('access:revoked', {
        dataVaultId: accessData.dataVaultId,
        listingId,
        researcher
      });
      
      logger.info(`Access revoked for listing ${listingId} and researcher ${researcher}`);
    } catch (error) {
      logger.error(`Failed to revoke access for listing ${listingId}:`, error);
      throw new Error(`Access revocation failed: ${error.message}`);
    }
  }

  /**
   * Orchestrate a privacy-preserving computation
   * @param {string} requestId - ID of the computation request
   * @param {string} researcher - Address of the researcher
   * @param {Array<string>} dataVaultIds - IDs of data vaults to include in computation
   * @param {string} computationType - Type of computation to perform
   * @returns {Promise<Object>} Computation metadata
   * @throws {Error} If orchestration fails or access is denied
   */
  async orchestrateComputation(requestId, researcher, dataVaultIds, computationType) {
    try {
      logger.info(`Orchestrating computation ${requestId} for researcher ${researcher}`);
      
      // Verify access rights for all data vaults
      await Promise.all(dataVaultIds.map(dataVaultId => 
        this.verifyAccessRights(dataVaultId, researcher)
      ));
      
      // Create computation metadata
      const computationMetadata = {
        id: requestId,
        researcher,
        dataVaultIds,
        computationType,
        status: 'preparing',
        startedAt: Date.now()
      };
      
      this.computations.set(requestId, computationMetadata);
      
      // Apply differential privacy settings based on computation type
      const privacyParameters = this.differentialPrivacy.generateParameters(computationType);
      
      // Set up the computation across SMPC nodes
      const computationSetup = await this.smpcOrchestrator.setupComputation({
        computation: {
          id: requestId,
          type: computationType,
          researcher,
          dataVaultIds
        },
        privacyParameters
      });
      
      // Update computation status
      computationMetadata.status = 'ready';
      computationMetadata.setup = computationSetup;
      
      // Emit event for downstream components
      this.emit('computation:ready', computationMetadata);
      
      logger.info(`Computation ${requestId} orchestrated successfully`);
      
      // Execute the computation asynchronously
      this.executePrivateComputation(requestId)
        .then(() => logger.info(`Computation ${requestId} executed successfully`))
        .catch(error => logger.error(`Computation ${requestId} execution failed:`, error));
      
      return computationMetadata;
    } catch (error) {
      logger.error(`Failed to orchestrate computation ${requestId}:`, error);
      throw new Error(`Computation orchestration failed: ${error.message}`);
    }
  }

  /**
   * Verify a researcher's access rights to a data vault
   * @param {string} dataVaultId - ID of the data vault
   * @param {string} researcher - Address of the researcher
   * @returns {Promise<boolean>} Whether access is granted
   * @throws {Error} If access is denied or verification fails
   */
  async verifyAccessRights(dataVaultId, researcher) {
    try {
      logger.info(`Verifying access rights for data vault ${dataVaultId} and researcher ${researcher}`);
      
      // Get listings for this data vault
      const listingIds = await this.contracts.marketplace.methods.getListingsByDataVault(dataVaultId).call();
      
      // Check each listing for approved access
      for (const listingId of listingIds) {
        const hasAccess = await this.contracts.marketplace.methods.hasAccess(listingId, researcher).call();
        
        if (hasAccess) {
          // Verify with ZKP
          const accessKeyId = `${listingId}-${researcher}`;
          const accessProofData = this.accessProofs.get(accessKeyId);
          
          if (accessProofData && accessProofData.expiresAt > Date.now()) {
            const isValid = await this.zkpVerifier.verifyAccessProof(accessProofData.proof);
            if (isValid) {
              logger.info(`Access rights verified for data vault ${dataVaultId} and researcher ${researcher}`);
              return true;
            }
          }
        }
      }
      
      throw new Error(`Researcher ${researcher} does not have active access to data vault ${dataVaultId}`);
    } catch (error) {
      logger.error(`Access verification failed for data vault ${dataVaultId}:`, error);
      throw new Error(`Access verification failed: ${error.message}`);
    }
  }

  /**
   * Execute a privacy-preserving computation
   * @param {string} computationId - ID of the computation
   * @returns {Promise<Object>} Computation results
   * @throws {Error} If execution fails
   */
  async executePrivateComputation(computationId) {
    try {
      logger.info(`Executing private computation ${computationId}`);
      
      // Get computation metadata
      const computation = this.computations.get(computationId);
      if (!computation) {
        throw new Error(`Computation ${computationId} not found`);
      }
      
      // Update status
      computation.status = 'executing';
      this.emit('computation:executing', { id: computationId });
      
      // Execute the computation via SMPC orchestrator
      const results = await this.smpcOrchestrator.executeComputation(computation.setup);
      
      // Apply additional privacy measures to results
      const privateResults = this.differentialPrivacy.applyToResults(
        results, 
        computation.computationType
      );
      
      // Update computation with results
      computation.status = 'completed';
      computation.results = privateResults;
      computation.completedAt = Date.now();
      
      // Emit event for downstream components
      this.emit('computation:completed', {
        id: computationId,
        results: privateResults
      });
      
      logger.info(`Computation ${computationId} executed successfully`);
      
      // Publish results
      await this.publishResults(computationId);
      
      return privateResults;
    } catch (error) {
      // Update computation status to failed
      const computation = this.computations.get(computationId);
      if (computation) {
        computation.status = 'failed';
        computation.error = error.message;
        
        // Emit event for downstream components
        this.emit('computation:failed', {
          id: computationId,
          error: error.message
        });
      }
      
      logger.error(`Failed to execute computation ${computationId}:`, error);
      throw new Error(`Computation execution failed: ${error.message}`);
    }
  }

  /**
   * Publish computation results
   * @param {string} computationId - ID of the computation
   * @returns {Promise<Object>} Publication details
   * @throws {Error} If publication fails
   */
  async publishResults(computationId) {
    try {
      logger.info(`Publishing results for computation ${computationId}`);
      
      // Get computation metadata
      const computation = this.computations.get(computationId);
      if (!computation || computation.status !== 'completed') {
        throw new Error(`Computation ${computationId} not complete or not found`);
      }
      
      // Generate proof of correct computation
      const computationProof = await this.zkpVerifier.generateComputationProof({
        computationId,
        computationType: computation.computationType,
        dataVaultIds: computation.dataVaultIds,
        resultHash: this.encryptionService.hashData(computation.results)
      });
      
      // Publish results to blockchain
      const receipt = await this.contracts.verifierRegistry.methods.publishResults(
        computationId,
        computation.researcher,
        this.encryptionService.hashData(computation.results),
        computationProof.proofData
      ).send({ from: this.config.publisherAccount });
      
      // Update computation with publication details
      computation.publication = {
        transactionHash: receipt.transactionHash,
        blockNumber: receipt.blockNumber,
        timestamp: Date.now(),
        proof: computationProof
      };
      
      // Emit event for downstream components
      this.emit('results:published', {
        computationId,
        transactionHash: receipt.transactionHash,
        proofId: computationProof.id
      });
      
      logger.info(`Results for computation ${computationId} published successfully`);
      
      return computation.publication;
    } catch (error) {
      logger.error(`Failed to publish results for computation ${computationId}:`, error);
      throw new Error(`Results publication failed: ${error.message}`);
    }
  }

  /**
   * Get registered data vault metadata
   * @param {string} dataVaultId - ID of the data vault
   * @returns {Object|null} Vault metadata or null if not found
   */
  getDataVault(dataVaultId) {
    return this.dataVaults.get(dataVaultId) || null;
  }

  /**
   * Get all registered data vaults
   * @returns {Array<Object>} Array of vault metadata objects
   */
  getAllDataVaults() {
    return Array.from(this.dataVaults.values());
  }

  /**
   * Get computation metadata
   * @param {string} computationId - ID of the computation
   * @returns {Object|null} Computation metadata or null if not found
   */
  getComputation(computationId) {
    return this.computations.get(computationId) || null;
  }

  /**
   * Get access request metadata
   * @param {string} requestId - ID of the access request
   * @returns {Object|null} Access request metadata or null if not found
   */
  getAccessRequest(requestId) {
    return this.accessRequests.get(requestId) || null;
  }

  /**
   * Register a callback for a specific event
   * @param {string} eventName - Name of the event
   * @param {Function} callback - Callback function
   * @returns {this} For method chaining
   */
  on(eventName, callback) {
    super.on(eventName, callback);
    logger.debug(`Registered callback for event '${eventName}'`);
    return this;
  }
}

module.exports = PrivacyLayer;
