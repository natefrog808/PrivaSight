/**
 * SMPCOrchestrator
 * 
 * Orchestrates Secure Multi-Party Computation (SMPC) across the PrivaSight network.
 * This component coordinates the secure computation process between multiple nodes
 * while ensuring privacy of the underlying data.
 */

const EventEmitter = require('events');
const { v4: uuidv4 } = require('uuid');
const logger = require('../../utils/logger')('privacy-layer:smpc-orchestrator');

/**
 * States for SMPC computation lifecycle
 * @enum {string}
 */
const ComputationState = {
  CREATED: 'created',
  INITIALIZING: 'initializing',
  SHARING: 'sharing',
  COMPUTING: 'computing',
  AGGREGATING: 'aggregating',
  VERIFYING: 'verifying',
  COMPLETED: 'completed',
  FAILED: 'failed',
  ABORTED: 'aborted'
};

/**
 * SMPC Orchestrator for coordinating secure computations
 * @class SMPCOrchestrator
 * @extends EventEmitter
 */
class SMPCOrchestrator extends EventEmitter {
  /**
   * Create a new SMPC Orchestrator
   * @param {Object} options - Configuration options
   * @param {Object} options.secretSharing - Secret sharing implementation
   * @param {Object} options.coordinator - SMPC coordinator
   * @param {Object} options.protocols - Map of computation protocols
   * @param {Object} [options.config] - Additional configuration
   */
  constructor({ secretSharing, coordinator, protocols, config = {} }) {
    super();

    this.secretSharing = secretSharing;
    this.coordinator = coordinator;
    this.protocols = protocols;
    this.config = {
      minNodes: 3,          // Minimum nodes required for computation
      maxNodesPerComputation: 7, // Maximum nodes per computation
      thresholdRatio: 0.66, // Default threshold ratio for node agreement
      minThreshold: 2,      // Minimum threshold for computation
      computationTimeout: 300000, // 5 minutes timeout
      maxErrors: 2,         // Maximum errors before aborting
      ...config             // Merge with user-provided config
    };

    // Initialize state tracking
    this.computations = new Map(); // computationId => computation metadata
    this.nodeRegistry = new Map(); // nodeId => node information
    this.activeNodes = new Set();  // Currently active node IDs

    // Bind methods to maintain context
    this.setupComputation = this.setupComputation.bind(this);
    this.executeComputation = this.executeComputation.bind(this);
    this.abortComputation = this.abortComputation.bind(this);
    this.registerNode = this.registerNode.bind(this);
    this.handleNodeDisconnect = this.handleNodeDisconnect.bind(this);

    // Set up event listeners for the coordinator
    this._setupCoordinatorEvents();

    logger.info('SMPC Orchestrator initialized');
  }

  /**
   * Set up event listeners for the coordinator
   * @private
   */
  _setupCoordinatorEvents() {
    this.coordinator.on('node:connected', (nodeId) => {
      this.activeNodes.add(nodeId);
      this.emit('node:connected', nodeId);
      logger.info(`Node ${nodeId} connected`);
    });

    this.coordinator.on('node:disconnected', (nodeId) => {
      this.handleNodeDisconnect(nodeId);
    });

    this.coordinator.on('share:received', ({ computationId, nodeId }) => {
      logger.debug(`Received share for computation ${computationId} from node ${nodeId}`);
      const computation = this.computations.get(computationId);
      if (computation) {
        computation.receivedShares++;
        if (computation.receivedShares >= computation.expectedShares) {
          this._advanceComputationState(computationId, ComputationState.COMPUTING);
        }
      }
    });

    this.coordinator.on('result:received', ({ computationId, nodeId, result }) => {
      logger.debug(`Received result for computation ${computationId} from node ${nodeId}`);
      const computation = this.computations.get(computationId);
      if (computation) {
        computation.nodeResults.set(nodeId, result);
        if (computation.nodeResults.size >= computation.assignedNodes.size) {
          this._advanceComputationState(computationId, ComputationState.AGGREGATING);
          this._aggregateResults(computationId);
        }
      }
    });

    this.coordinator.on('error', ({ computationId, nodeId, error }) => {
      logger.error(`Error in computation ${computationId} from node ${nodeId}:`, error);
      const computation = this.computations.get(computationId);
      if (computation) {
        computation.errors.push({ nodeId, error, timestamp: Date.now() });
        if (
          computation.errors.length > this.config.maxErrors ||
          computation.assignedNodes.size - computation.errors.length < computation.threshold
        ) {
          this.abortComputation(computationId, `Too many node errors: ${error.message}`);
        }
      }
    });
  }

  /**
   * Register a computation node
   * @param {Object} nodeInfo - Node information
   * @param {string} nodeInfo.id - Node ID
   * @param {string} nodeInfo.url - Node URL
   * @param {Array<string>} nodeInfo.supportedProtocols - Protocols supported by the node
   * @param {Object} nodeInfo.capabilities - Node capabilities (e.g., computePower)
   * @returns {boolean} Whether registration was successful
   */
  registerNode(nodeInfo) {
    try {
      logger.info(`Registering computation node ${nodeInfo.id}`);

      if (!nodeInfo.id || !nodeInfo.url || !nodeInfo.supportedProtocols || !nodeInfo.capabilities) {
        throw new Error('Invalid node information');
      }

      if (this.nodeRegistry.has(nodeInfo.id)) {
        throw new Error(`Node ${nodeInfo.id} already registered`);
      }

      this.nodeRegistry.set(nodeInfo.id, {
        ...nodeInfo,
        status: 'registered',
        lastSeen: Date.now(),
        registeredAt: Date.now()
      });

      this.coordinator.connectNode(nodeInfo.id, nodeInfo.url)
        .then(() => logger.info(`Connected to node ${nodeInfo.id}`))
        .catch((error) => logger.error(`Failed to connect to node ${nodeInfo.id}:`, error));

      this.emit('node:registered', nodeInfo);
      return true;
    } catch (error) {
      logger.error(`Failed to register node:`, error);
      return false;
    }
  }

  /**
   * Handle node disconnection
   * @param {string} nodeId - ID of the disconnected node
   * @private
   */
  handleNodeDisconnect(nodeId) {
    this.activeNodes.delete(nodeId);

    const nodeInfo = this.nodeRegistry.get(nodeId);
    if (nodeInfo) {
      nodeInfo.status = 'disconnected';
      nodeInfo.lastSeen = Date.now();
    }

    for (const [computationId, computation] of this.computations.entries()) {
      if (
        computation.assignedNodes.has(nodeId) &&
        [ComputationState.INITIALIZING, ComputationState.SHARING, ComputationState.COMPUTING].includes(computation.state)
      ) {
        if (computation.assignedNodes.size - 1 < computation.threshold) {
          this.abortComputation(computationId, `Node ${nodeId} disconnected, not enough nodes to meet threshold`);
        } else {
          logger.warn(`Node ${nodeId} disconnected during computation ${computationId}, but computation can continue`);
          computation.assignedNodes.delete(nodeId);
        }
      }
    }

    this.emit('node:disconnected', nodeId);
    logger.info(`Node ${nodeId} disconnected`);
  }

  /**
   * Set up a new secure computation
   * @param {Object} params - Setup parameters
   * @param {Object} params.computation - Computation details
   * @param {string} params.computation.id - Computation ID
   * @param {string} params.computation.type - Computation type (e.g., 'average', 'statistical')
   * @param {string} params.computation.researcher - Researcher address
   * @param {Array<string>} params.computation.dataVaultIds - Data vault IDs
   * @param {Object} params.privacyParameters - Privacy parameters (e.g., epsilon)
   * @returns {Promise<Object>} Computation setup details
   */
  async setupComputation({ computation, privacyParameters }) {
    try {
      logger.info(`Setting up computation ${computation.id}`);

      if (!computation.id || !computation.type || !computation.dataVaultIds || !computation.dataVaultIds.length) {
        throw new Error('Invalid computation details');
      }

      if (!this.protocols[computation.type]) {
        throw new Error(`Unsupported computation type: ${computation.type}`);
      }

      const sessionKey = uuidv4();
      const assignedNodes = await this._selectNodesForComputation(computation);

      if (assignedNodes.size < this.config.minNodes) {
        throw new Error(`Not enough nodes available: found ${assignedNodes.size}, need ${this.config.minNodes}`);
      }

      const threshold = Math.max(
        Math.ceil(assignedNodes.size * this.config.thresholdRatio),
        this.config.minThreshold
      );

      const computationMeta = {
        id: computation.id,
        sessionKey,
        type: computation.type,
        dataVaultIds: computation.dataVaultIds,
        researcher: computation.researcher,
        state: ComputationState.CREATED,
        threshold,
        privacyParameters,
        assignedNodes,
        nodeResults: new Map(),
        receivedShares: 0,
        expectedShares: assignedNodes.size * computation.dataVaultIds.length,
        errors: [],
        protocol: this.protocols[computation.type],
        startedAt: Date.now(),
        stateHistory: [{ state: ComputationState.CREATED, timestamp: Date.now() }]
      };

      this.computations.set(computation.id, computationMeta);

      const setup = {
        id: computation.id,
        sessionKey,
        type: computation.type,
        dataVaultIds: computation.dataVaultIds,
        threshold,
        nodeIds: Array.from(assignedNodes),
        privacyParameters
      };

      this.emit('computation:setup', { id: computation.id, setup });
      logger.info(`Computation ${computation.id} setup completed with ${assignedNodes.size} nodes`);

      return setup;
    } catch (error) {
      logger.error(`Failed to set up computation:`, error);
      throw new Error(`Computation setup failed: ${error.message}`);
    }
  }

  /**
   * Execute a secure computation
   * @param {Object} setup - Computation setup from setupComputation
   * @returns {Promise<Object>} Computation results
   */
  async executeComputation(setup) {
    try {
      logger.info(`Executing computation ${setup.id}`);

      const computation = this.computations.get(setup.id);
      if (!computation) {
        throw new Error(`Computation ${setup.id} not found`);
      }

      this._advanceComputationState(setup.id, ComputationState.INITIALIZING);
      await this._initializeNodesForComputation(setup);

      this._advanceComputationState(setup.id, ComputationState.SHARING);
      await this._shareDataBetweenNodes(setup);

      const result = await this._waitForComputationResult(setup.id);

      logger.info(`Computation ${setup.id} completed successfully`);
      return result;
    } catch (error) {
      const computation = this.computations.get(setup.id);
      if (computation) {
        this._advanceComputationState(setup.id, ComputationState.FAILED);
      }
      logger.error(`Failed to execute computation:`, error);
      throw new Error(`Computation execution failed: ${error.message}`);
    }
  }

  /**
   * Abort an ongoing computation
   * @param {string} computationId - ID of the computation to abort
   * @param {string} reason - Reason for aborting
   * @returns {Promise<boolean>} Whether abortion was successful
   */
  async abortComputation(computationId, reason) {
    try {
      logger.info(`Aborting computation ${computationId}: ${reason}`);

      const computation = this.computations.get(computationId);
      if (!computation) {
        throw new Error(`Computation ${computationId} not found`);
      }

      if ([ComputationState.COMPLETED, ComputationState.FAILED, ComputationState.ABORTED].includes(computation.state)) {
        logger.warn(`Computation ${computationId} is already in state ${computation.state}, cannot abort`);
        return false;
      }

      const abortPromises = Array.from(computation.assignedNodes).map((nodeId) =>
        this.coordinator.sendCommand(nodeId, 'abort', { computationId, reason })
      );

      await Promise.allSettled(abortPromises);

      this._advanceComputationState(computationId, ComputationState.ABORTED);
      computation.abortReason = reason;

      this.emit('computation:aborted', { id: computationId, reason });
      logger.info(`Computation ${computationId} aborted successfully`);

      return true;
    } catch (error) {
      logger.error(`Failed to abort computation:`, error);
      return false;
    }
  }

  /**
   * Get the status of a computation
   * @param {string} computationId - ID of the computation
   * @returns {Object|null} Computation status or null if not found
   */
  getComputationStatus(computationId) {
    const computation = this.computations.get(computationId);
    if (!computation) return null;

    return {
      id: computation.id,
      state: computation.state,
      startedAt: computation.startedAt,
      completedAt: computation.completedAt,
      nodeCount: computation.assignedNodes.size,
      progress: this._calculateComputationProgress(computation),
      errors: computation.errors.length > 0
    };
  }

  /**
   * Get detailed information about a computation
   * @param {string} computationId - ID of the computation
   * @returns {Object|null} Computation details or null if not found
   */
  getComputationDetails(computationId) {
    return this.computations.get(computationId) || null;
  }

  /**
   * Get available computation nodes
   * @param {string} [protocol] - Filter by supported protocol
   * @returns {Array<Object>} Array of node information
   */
  getAvailableNodes(protocol) {
    const nodes = [];
    for (const [nodeId, nodeInfo] of this.nodeRegistry.entries()) {
      if (this.activeNodes.has(nodeId)) {
        if (!protocol || nodeInfo.supportedProtocols.includes(protocol)) {
          nodes.push({
            id: nodeId,
            url: nodeInfo.url,
            supportedProtocols: nodeInfo.supportedProtocols,
            capabilities: nodeInfo.capabilities
          });
        }
      }
    }
    return nodes;
  }

  /**
   * Select nodes for a computation
   * @param {Object} computation - Computation details
   * @returns {Promise<Set<string>>} Set of selected node IDs
   * @private
   */
  async _selectNodesForComputation(computation) {
    const availableNodes = this.getAvailableNodes(computation.type);
    const targetNodeCount = Math.min(availableNodes.length, this.config.maxNodesPerComputation);

    if (targetNodeCount < this.config.minNodes) {
      throw new Error(`Not enough nodes available: found ${availableNodes.length}, need ${this.config.minNodes}`);
    }

    const nodeScores = await Promise.all(
      availableNodes.map(async (node) => {
        const nodeLoad = await this.coordinator.getNodeLoad(node.id).catch(() => 1);
        const capabilityScore = node.capabilities.computePower || 1;
        const score = capabilityScore * (1 - nodeLoad);
        return { node, score };
      })
    );

    const selectedNodes = nodeScores
      .sort((a, b) => b.score - a.score)
      .slice(0, targetNodeCount)
      .map((item) => item.node.id);

    return new Set(selectedNodes);
  }

  /**
   * Initialize nodes for computation
   * @param {Object} setup - Computation setup
   * @returns {Promise<void>}
   * @private
   */
  async _initializeNodesForComputation(setup) {
    logger.info(`Initializing ${setup.nodeIds.length} nodes for computation ${setup.id}`);

    const initPromises = setup.nodeIds.map((nodeId) =>
      this.coordinator.sendCommand(nodeId, 'initialize', {
        computationId: setup.id,
        sessionKey: setup.sessionKey,
        type: setup.type,
        threshold: setup.threshold,
        dataVaultIds: setup.dataVaultIds,
        privacyParameters: setup.privacyParameters,
        peers: setup.nodeIds.filter((id) => id !== nodeId)
      })
    );

    await Promise.all(initPromises);
    logger.info(`All nodes initialized for computation ${setup.id}`);
  }

  /**
   * Share data between nodes for computation
   * @param {Object} setup - Computation setup
   * @returns {Promise<void>}
   * @private
   */
  async _shareDataBetweenNodes(setup) {
    logger.info(`Starting data sharing for computation ${setup.id}`);

    const sharePromises = setup.nodeIds.map((nodeId) =>
      this.coordinator.sendCommand(nodeId, 'share', {
        computationId: setup.id,
        sessionKey: setup.sessionKey
      })
    );

    await Promise.all(sharePromises);
    logger.info(`Data sharing initiated for computation ${setup.id}`);
  }

  /**
   * Wait for computation result
   * @param {string} computationId - ID of the computation
   * @returns {Promise<Object>} Computation result
   * @private
   */
  async _waitForComputationResult(computationId) {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error(`Computation ${computationId} timed out`)),
        this.config.computationTimeout
      );

      const resultListener = (result) => {
        if (result.id === computationId) {
          clearTimeout(timeout);
          this.removeListener('computation:completed', resultListener);
          resolve(result.result);
        }
      };

      const errorListener = (error) => {
        if (error.id === computationId) {
          clearTimeout(timeout);
          this.removeListener('computation:completed', resultListener);
          this.removeListener('computation:failed', errorListener);
          reject(new Error(`Computation failed: ${error.message}`));
        }
      };

      this.on('computation:completed', resultListener);
      this.on('computation:failed', errorListener);

      const computation = this.computations.get(computationId);
      if (computation && computation.state === ComputationState.COMPLETED) {
        clearTimeout(timeout);
        this.removeListener('computation:completed', resultListener);
        this.removeListener('computation:failed', errorListener);
        resolve(computation.result);
      }
    });
  }

  /**
   * Aggregate results from all nodes
   * @param {string} computationId - ID of the computation
   * @private
   */
  async _aggregateResults(computationId) {
    try {
      logger.info(`Aggregating results for computation ${computationId}`);

      const computation = this.computations.get(computationId);
      if (!computation) {
        throw new Error(`Computation ${computationId} not found`);
      }

      const protocol = this.protocols[computation.type];
      const nodeResults = Array.from(computation.nodeResults.values());
      const result = await protocol.aggregateResults(nodeResults, computation.privacyParameters);

      computation.result = result;
      computation.completedAt = Date.now();

      this._advanceComputationState(computationId, ComputationState.VERIFYING);
      const isValid = await this._verifyComputationResult(computationId, result);

      if (isValid) {
        this._advanceComputationState(computationId, ComputationState.COMPLETED);
        this.emit('computation:completed', { id: computationId, result });
        logger.info(`Computation ${computationId} completed with valid result`);
      } else {
        throw new Error('Computation result verification failed');
      }
    } catch (error) {
      logger.error(`Failed to aggregate results for computation ${computationId}:`, error);
      this._advanceComputationState(computationId, ComputationState.FAILED);
      this.emit('computation:failed', { id: computationId, error: error.message });
    }
  }

  /**
   * Verify a computation result
   * @param {string} computationId - ID of the computation
   * @param {Object} result - Computation result
   * @returns {Promise<boolean>} Whether the result is valid
   * @private
   */
  async _verifyComputationResult(computationId, result) {
    try {
      logger.info(`Verifying result for computation ${computationId}`);

      const computation = this.computations.get(computationId);
      if (!computation) {
        throw new Error(`Computation ${computationId} not found`);
      }

      const protocol = this.protocols[computation.type];
      const isValid = await protocol.verifyResult(result, {
        nodeResults: Array.from(computation.nodeResults.values()),
        privacyParameters: computation.privacyParameters
      });

      return isValid;
    } catch (error) {
      logger.error(`Failed to verify result for computation ${computationId}:`, error);
      return false;
    }
  }

  /**
   * Advance a computation's state
   * @param {string} computationId - ID of the computation
   * @param {string} newState - New state
   * @private
   */
  _advanceComputationState(computationId, newState) {
    const computation = this.computations.get(computationId);
    if (!computation) return;

    const oldState = computation.state;
    computation.state = newState;
    computation.stateHistory.push({
      state: newState,
      timestamp: Date.now(),
      transitionFrom: oldState
    });

    this.emit('computation:state-changed', { id: computationId, oldState, newState });
    logger.info(`Computation ${computationId} state changed: ${oldState} -> ${newState}`);
  }

  /**
   * Calculate computation progress percentage
   * @param {Object} computation - Computation metadata
   * @returns {number} Progress percentage (0-100)
   * @private
   */
  _calculateComputationProgress(computation) {
    const stateWeights = {
      [ComputationState.CREATED]: 0,
      [ComputationState.INITIALIZING]: 10,
      [ComputationState.SHARING]: 30,
      [ComputationState.COMPUTING]: 50,
      [ComputationState.AGGREGATING]: 80,
      [ComputationState.VERIFYING]: 90,
      [ComputationState.COMPLETED]: 100,
      [ComputationState.FAILED]: 0,
      [ComputationState.ABORTED]: 0
    };

    let progress = stateWeights[computation.state] || 0;

    if (computation.state === ComputationState.SHARING && computation.expectedShares > 0) {
      progress += (computation.receivedShares / computation.expectedShares) * 20;
    } else if (computation.state === ComputationState.COMPUTING && computation.assignedNodes.size > 0) {
      progress += (computation.nodeResults.size / computation.assignedNodes.size) * 30;
    }

    return Math.min(Math.round(progress), 100);
  }
}

module.exports = SMPCOrchestrator;
