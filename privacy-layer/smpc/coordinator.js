/**
 * PrivaSight SMPC Coordinator
 *
 * This module implements the coordinator for secure multi-party computation.
 * The coordinator manages computation nodes, distributes tasks, handles node
 * failures, synchronizes computation phases, and aggregates results while
 * maintaining privacy guarantees.
 */

const EventEmitter = require('events');
const WebSocket = require('ws');
const http = require('http');
const url = require('url');
const { v4: uuidv4 } = require('uuid');
const { randomFieldElement } = require('../zkp/utils/hash');
const logger = require('../../utils/logger')('privacy-layer:smpc-coordinator');

// Computation state constants
const ComputationState = {
  CREATED: 'created',
  INITIALIZING: 'initializing',
  AWAITING_NODES: 'awaiting_nodes',
  DISTRIBUTING: 'distributing',
  PROCESSING: 'processing',
  COLLECTING: 'collecting',
  AGGREGATING: 'aggregating',
  VERIFYING: 'verifying',
  COMPLETED: 'completed',
  FAILED: 'failed',
  ABORTED: 'aborted'
};

// Node state constants
const NodeState = {
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  IDLE: 'idle',
  BUSY: 'busy',
  ERROR: 'error'
};

/**
 * SMPC Coordinator for orchestrating distributed computations
 * @class Coordinator
 * @extends EventEmitter
 */
class Coordinator extends EventEmitter {
  /**
   * Create a new SMPC Coordinator
   * @param {Object} options - Configuration options
   * @param {number} [options.port=8080] - Port to listen on
   * @param {string} [options.host='0.0.0.0'] - Host to bind to
   * @param {number} [options.minNodes=3] - Minimum nodes required
   * @param {number} [options.nodeTimeout=30000] - Node response timeout (ms)
   * @param {number} [options.computationTimeout=300000] - Computation timeout (ms)
   * @param {boolean} [options.enableFaultTolerance=true] - Enable fault tolerance
   * @param {number} [options.maxConcurrentComputations=10] - Max concurrent computations
   */
  constructor({
    port = 8080,
    host = '0.0.0.0',
    minNodes = 3,
    nodeTimeout = 30000,
    computationTimeout = 300000,
    enableFaultTolerance = true,
    maxConcurrentComputations = 10,
    authentication = {},
    encryption = {}
  } = {}) {
    super();

    this.port = port;
    this.host = host;
    this.minNodes = minNodes;
    this.nodeTimeout = nodeTimeout;
    this.computationTimeout = computationTimeout;
    this.enableFaultTolerance = enableFaultTolerance;
    this.maxConcurrentComputations = maxConcurrentComputations;
    this.authentication = authentication;
    this.encryption = encryption;

    // Initialize state
    this.server = null;
    this.wss = null;
    this.isRunning = false;
    this.nodes = new Map();
    this.activeComputations = new Map();
    this.computationQueue = [];
    this.pendingResponses = new Map();

    // Bind methods
    this.start = this.start.bind(this);
    this.stop = this.stop.bind(this);
    this.createComputation = this.createComputation.bind(this);
    this.abortComputation = this.abortComputation.bind(this);
    this.getComputationStatus = this.getComputationStatus.bind(this);
    this.getNodeInfo = this.getNodeInfo.bind(this);

    logger.info('SMPC Coordinator initialized', { port, host, minNodes });
  }

  /** Start the coordinator server */
  async start() {
    try {
      logger.info(`Starting coordinator on ${this.host}:${this.port}`);

      this.server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url, true);
        if (parsedUrl.pathname === '/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'ok',
            nodes: this.nodes.size,
            activeComputations: this.activeComputations.size
          }));
        } else if (parsedUrl.pathname === '/status') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'ok',
            nodes: Array.from(this.nodes.entries()).map(([id, node]) => ({
              id,
              state: node.state,
              activeComputations: node.activeComputations.size
            })),
            activeComputations: Array.from(this.activeComputations.entries()).map(([id, comp]) => ({
              id,
              state: comp.state,
              type: comp.type
            }))
          }));
        } else {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not Found');
        }
      });

      this.wss = new WebSocket.Server({ server: this.server });
      this.wss.on('connection', this._handleConnection.bind(this));
      this.wss.on('error', this._handleServerError.bind(this));

      await new Promise((resolve, reject) => {
        this.server.listen(this.port, this.host, (err) => {
          err ? reject(err) : resolve();
        });
      });

      this.isRunning = true;
      this._setupPeriodicTasks();
      logger.info(`Coordinator started on ${this.host}:${this.port}`);
      this.emit('started');
    } catch (error) {
      logger.error('Failed to start coordinator', error);
      await this.stop();
      throw error;
    }
  }

  /** Stop the coordinator server */
  async stop() {
    logger.info('Stopping coordinator');

    if (this.pingInterval) clearInterval(this.pingInterval);
    if (this.timeoutCheckInterval) clearInterval(this.timeoutCheckInterval);

    if (this.wss) {
      await new Promise(resolve => this.wss.close(resolve));
      this.wss = null;
    }

    if (this.server) {
      await new Promise(resolve => this.server.close(resolve));
      this.server = null;
    }

    for (const [id] of this.activeComputations) {
      await this.abortComputation(id, 'Coordinator shutdown');
    }

    this.isRunning = false;
    this.emit('stopped');
    logger.info('Coordinator stopped');
  }

  /** Create a new computation */
  async createComputation(params) {
    try {
      if (!params.type) throw new Error('Computation type required');

      const availableNodes = this._getAvailableNodes(params.type);
      const requiredNodes = params.requiredNodes || [];
      const preferredNodes = params.preferredNodes || [];
      const minNodes = params.minNodes || this.minNodes;
      const maxNodes = params.maxNodes || availableNodes.length;

      for (const nodeId of requiredNodes) {
        if (!this.nodes.has(nodeId) || this.nodes.get(nodeId).state !== NodeState.IDLE) {
          throw new Error(`Required node ${nodeId} unavailable`);
        }
      }

      if (availableNodes.length < minNodes) {
        throw new Error(`Need ${minNodes} nodes, found ${availableNodes.length}`);
      }

      if (this.activeComputations.size >= this.maxConcurrentComputations) {
        const queued = { id: uuidv4(), params, queuedAt: Date.now() };
        this.computationQueue.push(queued);
        return { computationId: queued.id, status: 'queued', queuedAt: queued.queuedAt };
      }

      const computationId = uuidv4();
      const selectedNodes = this._selectNodesForComputation({
        availableNodes,
        requiredNodes,
        preferredNodes,
        minNodes,
        maxNodes
      });

      const sessionKey = randomFieldElement().toString();
      const threshold = params.threshold || Math.ceil(selectedNodes.length / 2) + 1;
      if (threshold > selectedNodes.length) throw new Error('Invalid threshold');

      const computation = {
        id: computationId,
        type: params.type,
        threshold,
        sessionKey,
        state: ComputationState.CREATED,
        assignedNodes: new Set(selectedNodes),
        nodeResponses: new Map(),
        nodeResults: new Map(),
        startedAt: Date.now(),
        updatedAt: Date.now(),
        timeoutAt: Date.now() + this.computationTimeout
      };

      this.activeComputations.set(computationId, computation);
      for (const nodeId of selectedNodes) {
        const node = this.nodes.get(nodeId);
        node.activeComputations.add(computationId);
        if (node.activeComputations.size >= node.capabilities.maxConcurrentComputations) {
          node.state = NodeState.BUSY;
        }
      }

      this._initializeComputation(computationId);
      this.emit('computation:created', { computationId, type: params.type });
      return { computationId, sessionKey, threshold, nodes: selectedNodes, status: 'created' };
    } catch (error) {
      logger.error('Failed to create computation', error);
      throw error;
    }
  }

  /** Abort a computation */
  async abortComputation(computationId, reason = 'User requested abort') {
    if (!this.activeComputations.has(computationId)) {
      return { success: false, error: `Computation ${computationId} not found` };
    }

    const computation = this.activeComputations.get(computationId);
    const previousState = computation.state;
    computation.state = ComputationState.ABORTED;
    computation.abortReason = reason;
    computation.abortedAt = Date.now();
    computation.updatedAt = Date.now();

    for (const nodeId of computation.assignedNodes) {
      const node = this.nodes.get(nodeId);
      if (node && node.socket && node.state !== NodeState.DISCONNECTED) {
        await this._sendToNode(nodeId, {
          type: 'command',
          command: 'abort',
          params: { computationId, reason }
        }).catch(err => logger.warn(`Failed to notify node ${nodeId}`, err));
        node.activeComputations.delete(computationId);
        if (node.activeComputations.size < node.capabilities.maxConcurrentComputations) {
          node.state = NodeState.IDLE;
        }
      }
    }

    this.activeComputations.delete(computationId);
    if (this.computationQueue.length > 0) {
      const next = this.computationQueue.shift();
      this.createComputation(next.params).catch(err => logger.error('Failed to process queued', err));
    }

    this.emit('computation:aborted', { computationId, reason });
    return { success: true, computationId, abortedAt: computation.abortedAt };
  }

  /** Get computation status */
  getComputationStatus(computationId) {
    if (!this.activeComputations.has(computationId)) {
      return { success: false, error: `Computation ${computationId} not found` };
    }

    const computation = this.activeComputations.get(computationId);
    return {
      success: true,
      computationId,
      state: computation.state,
      nodeCount: computation.assignedNodes.size,
      progress: this._calculateComputationProgress(computation)
    };
  }

  /** Get node info */
  getNodeInfo(nodeId) {
    if (!this.nodes.has(nodeId)) {
      return { success: false, error: `Node ${nodeId} not found` };
    }

    const node = this.nodes.get(nodeId);
    return {
      success: true,
      nodeId,
      state: node.state,
      activeComputations: Array.from(node.activeComputations)
    };
  }

  /** Private: Handle WebSocket connection */
  _handleConnection(socket) {
    const connectionId = uuidv4();
    socket.on('message', data => this._handleNodeMessage(connectionId, socket, JSON.parse(data)));
    socket.on('close', () => this._handleNodeDisconnect(connectionId));
    this.nodes.set(connectionId, {
      id: connectionId,
      socket,
      state: NodeState.CONNECTING,
      connectedAt: Date.now(),
      lastSeen: Date.now(),
      capabilities: { maxConcurrentComputations: 5 },
      supportedProtocols: [],
      activeComputations: new Set()
    });
  }

  /** Private: Handle node messages */
  _handleNodeMessage(connectionId, socket, message) {
    switch (message.type) {
      case 'registration':
        this._handleNodeRegistration(connectionId, socket, message);
        break;
      case 'share_notification':
        this._handleShareNotification(connectionId, message);
        break;
      case 'result':
        this._handleResultMessage(connectionId, message);
        break;
      case 'verification_result':
        this._handleVerificationResult(connectionId, message);
        break;
    }
  }

  /** Private: Handle node registration */
  _handleNodeRegistration(connectionId, socket, message) {
    const { nodeId, capabilities, supportedProtocols } = message;
    if (!nodeId) throw new Error('Node ID required');

    if (this.nodes.has(nodeId) && nodeId !== connectionId) {
      const existing = this.nodes.get(nodeId);
      if (existing.socket) existing.socket.close();
      this.nodes.delete(nodeId);
    }

    const nodeInfo = this.nodes.get(connectionId);
    this.nodes.delete(connectionId);
    this.nodes.set(nodeId, {
      ...nodeInfo,
      id: nodeId,
      capabilities: capabilities || { maxConcurrentComputations: 5 },
      supportedProtocols: supportedProtocols || [],
      state: NodeState.IDLE
    });

    this._sendToNode(nodeId, { type: 'registration_confirmed', nodeId });
    this.emit('node:connected', { nodeId });
  }

  /** Private: Handle share notification */
  _handleShareNotification(nodeId, message) {
    const { computationId, shareId } = message;
    const computation = this.activeComputations.get(computationId);
    if (!computation || !computation.assignedNodes.has(nodeId)) return;

    computation.nodeResponses.set(nodeId, { type: 'share', shareId });
    if (computation.nodeResponses.size === computation.assignedNodes.size) {
      this._advanceComputation(computationId, ComputationState.PROCESSING);
      for (const assignedNodeId of computation.assignedNodes) {
        this._sendToNode(assignedNodeId, { type: 'command', command: 'compute', params: { computationId } });
      }
    }
  }

  /** Private: Select nodes for computation */
  _selectNodesForComputation({ availableNodes, requiredNodes, preferredNodes, minNodes, maxNodes }) {
    const selectedNodes = [...requiredNodes];

    for (const nodeId of preferredNodes) {
      if (!selectedNodes.includes(nodeId) && availableNodes.find(n => n.id === nodeId)) {
        selectedNodes.push(nodeId);
      }
    }

    if (selectedNodes.length < minNodes) {
      const sortedNodes = availableNodes
        .filter(node => !selectedNodes.includes(node.id))
        .sort((a, b) => {
          const scoreA = (1 - a.load) * (a.capabilities.computePower || 1);
          const scoreB = (1 - b.load) * (b.capabilities.computePower || 1);
          return scoreB - scoreA;
        });

      for (const node of sortedNodes) {
        if (selectedNodes.length >= minNodes) break;
        selectedNodes.push(node.id);
      }
    }

    return selectedNodes.slice(0, maxNodes);
  }

  /** Private: Get available nodes */
  _getAvailableNodes(computationType) {
    const availableNodes = [];
    for (const [nodeId, node] of this.nodes.entries()) {
      if (node.state === NodeState.DISCONNECTED) continue;
      if (!node.supportedProtocols.includes(computationType)) continue;
      if (node.activeComputations.size >= node.capabilities.maxConcurrentComputations) continue;

      const load = node.activeComputations.size / node.capabilities.maxConcurrentComputations;
      availableNodes.push({ id: nodeId, load, capabilities: node.capabilities, supportedProtocols: node.supportedProtocols });
    }
    return availableNodes;
  }

  /** Private: Select aggregator node */
  _selectAggregatorNode(computation) {
    const assignedNodeIds = Array.from(computation.assignedNodes);
    if (assignedNodeIds.length === 1) return assignedNodeIds[0];

    let lowestLoad = Infinity;
    let selectedNodeId = assignedNodeIds[0];
    for (const nodeId of assignedNodeIds) {
      const node = this.nodes.get(nodeId);
      if (node.state === NodeState.DISCONNECTED) continue;
      const load = node.activeComputations.size / node.capabilities.maxConcurrentComputations;
      if (load < lowestLoad) {
        lowestLoad = load;
        selectedNodeId = nodeId;
      }
    }
    return selectedNodeId;
  }

  /** Private: Calculate computation progress */
  _calculateComputationProgress(computation) {
    const stateWeights = {
      [ComputationState.CREATED]: 0,
      [ComputationState.INITIALIZING]: 10,
      [ComputationState.AWAITING_NODES]: 20,
      [ComputationState.DISTRIBUTING]: 30,
      [ComputationState.PROCESSING]: 50,
      [ComputationState.COLLECTING]: 70,
      [ComputationState.AGGREGATING]: 80,
      [ComputationState.VERIFYING]: 90,
      [ComputationState.COMPLETED]: 100,
      [ComputationState.FAILED]: 100,
      [ComputationState.ABORTED]: 100
    };

    let progress = stateWeights[computation.state] || 0;
    if (computation.state === ComputationState.AWAITING_NODES && computation.assignedNodes.size > 0) {
      const responseRatio = computation.nodeResponses.size / computation.assignedNodes.size;
      progress += responseRatio * (stateWeights[ComputationState.DISTRIBUTING] - stateWeights[ComputationState.AWAITING_NODES]);
    }
    return Math.min(100, Math.max(0, progress));
  }

  /** Private: Verify computation result */
  async _verifyResult(computationId) {
    const computation = this.activeComputations.get(computationId);
    const verifyPromises = [];
    for (const nodeId of computation.assignedNodes) {
      verifyPromises.push(
        this._sendToNode(nodeId, {
          type: 'command',
          command: 'verify',
          params: { computationId, result: computation.result }
        }).catch(err => logger.error(`Verification failed for ${nodeId}`, err))
      );
    }
    await Promise.allSettled(verifyPromises);
  }

  /** Private: Complete computation */
  async _completeComputation(computationId) {
    const computation = this.activeComputations.get(computationId);
    this._advanceComputation(computationId, ComputationState.COMPLETED);
    computation.completedAt = Date.now();

    for (const nodeId of computation.assignedNodes) {
      const node = this.nodes.get(nodeId);
      if (node) {
        node.activeComputations.delete(computationId);
        if (node.activeComputations.size < node.capabilities.maxConcurrentComputations) {
          node.state = NodeState.IDLE;
        }
      }
    }

    this.emit('computation:completed', { computationId, result: computation.result });
    if (this.computationQueue.length > 0) {
      const next = this.computationQueue.shift();
      this.createComputation(next.params);
    }
  }

  /** Private: Send message to node */
  async _sendToNode(nodeId, message) {
    return new Promise((resolve, reject) => {
      const node = this.nodes.get(nodeId);
      if (!node || node.state === NodeState.DISCONNECTED || !node.socket || node.socket.readyState !== WebSocket.OPEN) {
        return reject(new Error(`Node ${nodeId} unavailable`));
      }

      message.messageId = message.messageId || uuidv4();
      this.pendingResponses.set(message.messageId, { resolve, reject });

      setTimeout(() => {
        if (this.pendingResponses.has(message.messageId)) {
          this.pendingResponses.delete(message.messageId);
          reject(new Error('Response timeout'));
        }
      }, this.nodeTimeout);

      node.socket.send(JSON.stringify(message), err => {
        if (err) {
          this.pendingResponses.delete(message.messageId);
          reject(err);
        }
      });
    });
  }

  /** Private: Advance computation state */
  _advanceComputation(computationId, newState) {
    const computation = this.activeComputations.get(computationId);
    const oldState = computation.state;
    computation.state = newState;
    computation.updatedAt = Date.now();
    this.emit('computation:state-changed', { computationId, oldState, newState });
  }

  /** Private: Check timeouts */
  _checkTimeouts() {
    const now = Date.now();
    for (const [id, comp] of this.activeComputations) {
      if (comp.state !== ComputationState.COMPLETED && comp.state !== ComputationState.ABORTED && now > comp.timeoutAt) {
        this.abortComputation(id, 'Computation timed out');
      }
    }
  }

  /** Private: Initialize computation */
  async _initializeComputation(computationId) {
    const computation = this.activeComputations.get(computationId);
    this._advanceComputation(computationId, ComputationState.INITIALIZING);

    const initPromises = [];
    for (const nodeId of computation.assignedNodes) {
      const peers = Array.from(computation.assignedNodes).filter(id => id !== nodeId);
      initPromises.push(
        this._sendToNode(nodeId, {
          type: 'command',
          command: 'initialize',
          params: { computationId, type: computation.type, sessionKey: computation.sessionKey, peers }
        })
      );
    }

    const results = await Promise.allSettled(initPromises);
    const failedNodes = results
      .map((r, i) => r.status === 'rejected' ? Array.from(computation.assignedNodes)[i] : null)
      .filter(Boolean);

    if (failedNodes.length > 0 && (!this.enableFaultTolerance || computation.assignedNodes.size - failedNodes.length < computation.threshold)) {
      this.abortComputation(computationId, `Initialization failed: ${failedNodes.join(', ')}`);
      return;
    }

    for (const nodeId of failedNodes) {
      computation.assignedNodes.delete(nodeId);
      const node = this.nodes.get(nodeId);
      if (node) node.activeComputations.delete(computationId);
    }

    this._advanceComputation(computationId, ComputationState.DISTRIBUTING);
    for (const nodeId of computation.assignedNodes) {
      this._sendToNode(nodeId, { type: 'command', command: 'share', params: { computationId, sessionKey: computation.sessionKey } });
    }
  }

  /** Private: Aggregate results */
  async _aggregateResults(computationId) {
    const computation = this.activeComputations.get(computationId);
    const results = Array.from(computation.nodeResults.values()).map(r => r.result);
    const aggregatorNodeId = this._selectAggregatorNode(computation);

    const aggregationResult = await this._sendToNode(aggregatorNodeId, {
      type: 'command',
      command: 'aggregate',
      params: { computationId, results }
    });

    computation.result = aggregationResult.result;
    this._advanceComputation(computationId, ComputationState.VERIFYING);
    await this._verifyResult(computationId);
  }

  /** Private: Handle result message */
  _handleResultMessage(nodeId, message) {
    const { computationId, result } = message;
    const computation = this.activeComputations.get(computationId);
    if (!computation || !computation.assignedNodes.has(nodeId)) return;

    computation.nodeResults.set(nodeId, { result, timestamp: Date.now() });
    if (computation.nodeResults.size === computation.assignedNodes.size) {
      this._advanceComputation(computationId, ComputationState.AGGREGATING);
      this._aggregateResults(computationId);
    }
  }

  /** Private: Handle verification result */
  _handleVerificationResult(nodeId, message) {
    const { computationId, verified } = message;
    const computation = this.activeComputations.get(computationId);
    if (!computation || !computation.assignedNodes.has(nodeId)) return;

    if (!computation.verificationResults) computation.verificationResults = new Map();
    computation.verificationResults.set(nodeId, { verified, timestamp: Date.now() });

    if (computation.verificationResults.size === computation.assignedNodes.size) {
      const allVerified = Array.from(computation.verificationResults.values()).every(r => r.verified);
      if (allVerified) {
        this._completeComputation(computationId);
      } else {
        this.abortComputation(computationId, 'Verification failed');
      }
    }
  }

  /** Private: Handle node disconnection */
  _handleNodeDisconnect(nodeId) {
    const node = this.nodes.get(nodeId);
    if (!node) return;

    node.state = NodeState.DISCONNECTED;
    for (const computationId of node.activeComputations) {
      const computation = this.activeComputations.get(computationId);
      if (computation) {
        computation.assignedNodes.delete(nodeId);
        if (this.enableFaultTolerance && computation.assignedNodes.size >= computation.threshold) {
          logger.warn(`Node ${nodeId} disconnected, continuing with ${computation.assignedNodes.size} nodes`);
        } else {
          this.abortComputation(computationId, `Node ${nodeId} disconnected`);
        }
      }
    }
    this.nodes.delete(nodeId);
    this.emit('node:disconnected', { nodeId });
  }

  /** Private: Handle server error */
  _handleServerError(error) {
    logger.error('Server error', error);
    this.emit('error', error);
  }

  /** Private: Setup periodic tasks */
  _setupPeriodicTasks() {
    this.pingInterval = setInterval(() => this._pingNodes(), 30000);
    this.timeoutCheckInterval = setInterval(() => this._checkTimeouts(), 10000);
  }

  /** Private: Ping nodes */
  _pingNodes() {
    for (const [nodeId, node] of this.nodes) {
      if (node.state !== NodeState.DISCONNECTED) {
        this._sendToNode(nodeId, { type: 'ping' })
          .then(() => node.lastSeen = Date.now())
          .catch(() => {
            if (Date.now() - (node.lastSeen || 0) > this.nodeTimeout) {
              this._handleNodeDisconnect(nodeId);
            }
          });
      }
    }
  }
}

/** Create a coordinator instance */
function createCoordinator(options = {}) {
  return new Coordinator(options);
}

module.exports = { Coordinator, createCoordinator, ComputationState, NodeState };
