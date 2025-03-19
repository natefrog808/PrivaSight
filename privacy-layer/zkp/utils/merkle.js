/**
 * PrivaSight ZKP Merkle Tree Utilities
 * 
 * Implements Merkle tree data structures and operations optimized for
 * zero-knowledge proofs. These utilities provide efficient methods for
 * creating, updating, and verifying Merkle trees and proofs, designed
 * to be compatible with ZK circuits.
 */

const { poseidonHash, poseidonHashSync, keccak256Hash } = require('./hash');
const { BigNumber } = require('ethers');
const logger = require('../../../utils/logger')('privacy-layer:zkp-merkle');

/**
 * MerkleTree class optimized for ZK proofs
 * @class MerkleTree
 */
class MerkleTree {
  /**
   * Create a new Merkle Tree
   * @param {Object} options - Configuration options
   * @param {number} [options.depth=32] - Depth of the tree (max leaf count = 2^depth)
   * @param {Function} [options.hashFunction=poseidonHashSync] - Hash function to use
   * @param {boolean} [options.zeroHashOptimization=true] - Whether to precompute zero hashes
   * @param {string} [options.defaultLeafValue='0'] - Default value for empty leaves
   * @param {boolean} [options.indexed=false] - Whether to use indexed Merkle tree
   * @throws {Error} If options are invalid
   */
  constructor({
    depth = 32,
    hashFunction = poseidonHashSync,
    zeroHashOptimization = true,
    defaultLeafValue = '0',
    indexed = false
  } = {}) {
    if (typeof depth !== 'number' || depth <= 0) throw new Error('Depth must be a positive number');
    if (typeof hashFunction !== 'function') throw new Error('hashFunction must be a function');
    if (typeof zeroHashOptimization !== 'boolean') throw new Error('zeroHashOptimization must be a boolean');
    if (typeof defaultLeafValue !== 'string') throw new Error('defaultLeafValue must be a string');
    if (typeof indexed !== 'boolean') throw new Error('indexed must be a boolean');

    this.depth = depth;
    this.hashFunction = hashFunction;
    this.zeroHashOptimization = zeroHashOptimization;
    this.defaultLeafValue = defaultLeafValue;
    this.indexed = indexed;
    
    // Initialize the tree
    this.leaves = new Map();
    this.nodes = new Map(); // Non-leaf nodes
    this.zeroHashes = []; // For zero-hash optimization
    
    // For indexed trees
    this.nextIndex = 0;
    this.indexToKey = new Map();
    this.keyToIndex = new Map();
    
    // Initialize with precomputed zero hashes if optimization is enabled
    if (this.zeroHashOptimization) {
      this._precomputeZeroHashes();
    }
    
    logger.info(`Initialized Merkle tree with depth ${depth} and ${indexed ? 'indexed' : 'non-indexed'} mode`);
  }

  /**
   * Add a leaf to the tree
   * @param {string} key - Key for the leaf
   * @param {string|number|BigNumber} value - Value to store in the leaf
   * @returns {number} Index of the inserted leaf
   * @throws {Error} If key or value is invalid
   */
  insert(key, value) {
    if (typeof key !== 'string') throw new Error('Key must be a string');
    const valueStr = BigNumber.isBigNumber(value) ? value.toString() : value.toString();
    
    let index;
    if (this.indexed) {
      if (this.keyToIndex.has(key)) {
        index = this.keyToIndex.get(key);
      } else {
        index = this.nextIndex++;
        this.keyToIndex.set(key, index);
        this.indexToKey.set(index, key);
      }
    } else {
      index = key;
    }
    
    this.leaves.set(index, valueStr);
    this._clearAffectedNodes(index);
    logger.debug(`Inserted leaf with key ${key} at index ${index}`);
    return index;
  }

  /**
   * Update a leaf in the tree
   * @param {string} key - Key for the leaf
   * @param {string|number|BigNumber} value - New value for the leaf
   * @returns {boolean} Whether the update was successful
   * @throws {Error} If key is invalid
   */
  update(key, value) {
    if (typeof key !== 'string') throw new Error('Key must be a string');
    const valueStr = BigNumber.isBigNumber(value) ? value.toString() : value.toString();
    
    let index;
    if (this.indexed) {
      if (!this.keyToIndex.has(key)) {
        logger.warn(`Cannot update leaf: key ${key} not found in tree`);
        return false;
      }
      index = this.keyToIndex.get(key);
    } else {
      index = key;
    }
    
    if (!this.leaves.has(index)) {
      logger.warn(`Cannot update leaf: index ${index} not found in tree`);
      return false;
    }
    
    this.leaves.set(index, valueStr);
    this._clearAffectedNodes(index);
    logger.debug(`Updated leaf with key ${key} at index ${index}`);
    return true;
  }

  /**
   * Remove a leaf from the tree
   * @param {string} key - Key for the leaf to remove
   * @returns {boolean} Whether the removal was successful
   * @throws {Error} If key is invalid
   */
  remove(key) {
    if (typeof key !== 'string') throw new Error('Key must be a string');
    
    let index;
    if (this.indexed) {
      if (!this.keyToIndex.has(key)) {
        logger.warn(`Cannot remove leaf: key ${key} not found in tree`);
        return false;
      }
      index = this.keyToIndex.get(key);
    } else {
      index = key;
    }
    
    if (!this.leaves.has(index)) {
      logger.warn(`Cannot remove leaf: index ${index} not found in tree`);
      return false;
    }
    
    this.leaves.delete(index);
    if (this.indexed) {
      this.keyToIndex.delete(key);
      this.indexToKey.delete(index);
    }
    
    this._clearAffectedNodes(index);
    logger.debug(`Removed leaf with key ${key} at index ${index}`);
    return true;
  }

  /**
   * Get a leaf from the tree
   * @param {string} key - Key for the leaf
   * @returns {string|null} Leaf value or null if not found
   * @throws {Error} If key is invalid
   */
  getLeaf(key) {
    if (typeof key !== 'string') throw new Error('Key must be a string');
    
    let index;
    if (this.indexed) {
      if (!this.keyToIndex.has(key)) return null;
      index = this.keyToIndex.get(key);
    } else {
      index = key;
    }
    
    return this.leaves.has(index) ? this.leaves.get(index) : null;
  }

  /**
   * Check if a leaf exists in the tree
   * @param {string} key - Key for the leaf
   * @returns {boolean} Whether the leaf exists
   * @throws {Error} If key is invalid
   */
  hasLeaf(key) {
    if (typeof key !== 'string') throw new Error('Key must be a string');
    
    let index;
    if (this.indexed) {
      if (!this.keyToIndex.has(key)) return false;
      index = this.keyToIndex.get(key);
    } else {
      index = key;
    }
    
    return this.leaves.has(index);
  }

  /**
   * Get the Merkle root of the tree
   * @returns {Promise<string>} The Merkle root
   */
  async getRoot() {
    return this._getNodeHashAsync(0, 0);
  }

  /**
   * Get the Merkle root of the tree (synchronous version)
   * @returns {string} The Merkle root
   */
  getRootSync() {
    return this._getNodeHash(0, 0);
  }

  /**
   * Get a Merkle proof for a leaf
   * @param {string} key - Key for the leaf
   * @returns {Promise<Object>} Merkle proof with path and indices
   * @throws {Error} If key is invalid or leaf not found
   */
  async getProof(key) {
    if (typeof key !== 'string') throw new Error('Key must be a string');
    
    let index;
    if (this.indexed) {
      if (!this.keyToIndex.has(key)) throw new Error(`Key ${key} not found in tree`);
      index = this.keyToIndex.get(key);
    } else {
      index = key;
    }
    
    if (!this.leaves.has(index)) throw new Error(`Index ${index} not found in tree`);
    
    const path = [];
    const indices = [];
    let positionBinary = this._getPositionBinary(index);
    
    let currentIndex = Number(index);
    for (let level = this.depth - 1; level >= 0; level--) {
      const isRightChild = positionBinary[this.depth - 1 - level] === '1';
      indices.push(isRightChild ? 1 : 0);
      const siblingPosition = isRightChild ? currentIndex - 1 : currentIndex + 1;
      const siblingHash = await this._getNodeHashAsync(level, siblingPosition);
      path.push(siblingHash);
      currentIndex = Math.floor(currentIndex / 2);
    }
    
    const leafValue = this.leaves.get(index);
    return {
      leaf: leafValue,
      path,
      indices,
      root: await this.getRoot()
    };
  }

  /**
   * Get a Merkle proof for a leaf (synchronous version)
   * @param {string} key - Key for the leaf
   * @returns {Object} Merkle proof with path and indices
   * @throws {Error} If key is invalid or leaf not found
   */
  getProofSync(key) {
    if (typeof key !== 'string') throw new Error('Key must be a string');
    
    let index;
    if (this.indexed) {
      if (!this.keyToIndex.has(key)) throw new Error(`Key ${key} not found in tree`);
      index = this.keyToIndex.get(key);
    } else {
      index = key;
    }
    
    if (!this.leaves.has(index)) throw new Error(`Index ${index} not found in tree`);
    
    const path = [];
    const indices = [];
    let positionBinary = this._getPositionBinary(index);
    
    let currentIndex = Number(index);
    for (let level = this.depth - 1; level >= 0; level--) {
      const isRightChild = positionBinary[this.depth - 1 - level] === '1';
      indices.push(isRightChild ? 1 : 0);
      const siblingPosition = isRightChild ? currentIndex - 1 : currentIndex + 1;
      const siblingHash = this._getNodeHash(level, siblingPosition);
      path.push(siblingHash);
      currentIndex = Math.floor(currentIndex / 2);
    }
    
    const leafValue = this.leaves.get(index);
    return {
      leaf: leafValue,
      path,
      indices,
      root: this.getRootSync()
    };
  }

  /**
   * Verify a Merkle proof
   * @param {Object} proof - The Merkle proof
   * @param {string} proof.leaf - Value of the leaf
   * @param {Array<string>} proof.path - Merkle proof path
   * @param {Array<number>} proof.indices - Indices for path direction (0 = left, 1 = right)
   * @param {string} proof.root - Expected Merkle root
   * @returns {Promise<boolean>} Whether the proof is valid
   */
  async verifyProof({ leaf, path, indices, root }) {
    try {
      let currentHash = leaf;
      for (let i = 0; i < path.length; i++) {
        const isRightChild = indices[i] === 1;
        const left = isRightChild ? path[i] : currentHash;
        const right = isRightChild ? currentHash : path[i];
        currentHash = await poseidonHash([left, right]);
      }
      return currentHash === root;
    } catch (error) {
      logger.error('Failed to verify Merkle proof:', error);
      return false;
    }
  }

  /**
   * Verify a Merkle proof (synchronous version)
   * @param {Object} proof - The Merkle proof
   * @param {string} proof.leaf - Value of the leaf
   * @param {Array<string>} proof.path - Merkle proof path
   * @param {Array<number>} proof.indices - Indices for path direction (0 = left, 1 = right)
   * @param {string} proof.root - Expected Merkle root
   * @returns {boolean} Whether the proof is valid
   */
  verifyProofSync({ leaf, path, indices, root }) {
    try {
      let currentHash = leaf;
      for (let i = 0; i < path.length; i++) {
        const isRightChild = indices[i] === 1;
        const left = isRightChild ? path[i] : currentHash;
        const right = isRightChild ? currentHash : path[i];
        currentHash = poseidonHashSync([left, right]);
      }
      return currentHash === root;
    } catch (error) {
      logger.error('Failed to verify Merkle proof:', error);
      return false;
    }
  }

  /**
   * Format a Merkle proof for use in ZK circuits
   * @param {Object} proof - The Merkle proof
   * @returns {Object} Formatted proof for ZK circuits
   * @throws {Error} If proof is invalid
   */
  formatProofForCircuit(proof) {
    if (!proof || !proof.path || !proof.indices || !proof.leaf || !proof.root) {
      throw new Error('Invalid proof structure');
    }
    const pathPadded = [...proof.path];
    const indicesPadded = [...proof.indices];
    while (pathPadded.length < this.depth) {
      pathPadded.push('0');
      indicesPadded.push(0);
    }
    return {
      leaf: proof.leaf,
      path: pathPadded,
      pathIndices: indicesPadded,
      root: proof.root
    };
  }

  /**
   * Get all leaves in the tree
   * @returns {Map<string|number, string>} Map of leaf indices to values
   */
  getLeaves() {
    return new Map(this.leaves);
  }

  /**
   * Get the total number of leaves in the tree
   * @returns {number} Number of leaves
   */
  getLeafCount() {
    return this.leaves.size;
  }

  /**
   * Clear the tree (remove all leaves)
   */
  clear() {
    this.leaves.clear();
    this.nodes.clear();
    if (this.indexed) {
      this.nextIndex = 0;
      this.indexToKey.clear();
      this.keyToIndex.clear();
    }
    logger.info('Merkle tree cleared');
  }

  /**
   * Export the tree to a serializable object
   * @returns {Object} Serialized tree
   */
  export() {
    return {
      depth: this.depth,
      leaves: Array.from(this.leaves.entries()),
      indexed: this.indexed,
      nextIndex: this.indexed ? this.nextIndex : undefined,
      indexToKey: this.indexed ? Array.from(this.indexToKey.entries()) : undefined,
      keyToIndex: this.indexed ? Array.from(this.keyToIndex.entries()) : undefined
    };
  }

  /**
   * Import a serialized tree
   * @param {Object} data - Serialized tree data
   * @throws {Error} If data is invalid
   */
  import(data) {
    if (!data || !data.depth || !Array.isArray(data.leaves)) {
      throw new Error('Invalid tree data for import');
    }
    this.clear();
    this.depth = data.depth;
    if (data.indexed) {
      this.indexed = true;
      this.nextIndex = data.nextIndex || 0;
      if (Array.isArray(data.indexToKey)) {
        for (const [index, key] of data.indexToKey) {
          this.indexToKey.set(index, key);
        }
      }
      if (Array.isArray(data.keyToIndex)) {
        for (const [key, index] of data.keyToIndex) {
          this.keyToIndex.set(key, index);
        }
      }
    }
    for (const [index, value] of data.leaves) {
      this.leaves.set(index, value);
    }
    logger.info(`Imported Merkle tree with ${this.leaves.size} leaves`);
  }

  /**
   * Calculate the hash of a node (async version)
   * @param {number} level - Level in the tree (0 = root)
   * @param {number} position - Position in the level
   * @returns {Promise<string>} Hash of the node
   * @private
   */
  async _getNodeHashAsync(level, position) {
    const nodeKey = `${level}-${position}`;
    if (this.nodes.has(nodeKey)) return this.nodes.get(nodeKey);
    if (level === this.depth - 1) {
      const leafValue = this.leaves.has(position) ? this.leaves.get(position) : this.defaultLeafValue;
      return leafValue;
    }
    if (this.zeroHashOptimization) {
      const leftChildKey = `${level + 1}-${position * 2}`;
      const rightChildKey = `${level + 1}-${position * 2 + 1}`;
      const leftEmpty = !this.nodes.has(leftChildKey) && !this._hasLeafInSubtree(level + 1, position * 2);
      const rightEmpty = !this.nodes.has(rightChildKey) && !this._hasLeafInSubtree(level + 1, position * 2 + 1);
      if (leftEmpty && rightEmpty) return this.zeroHashes[level];
    }
    const leftChild = await this._getNodeHashAsync(level + 1, position * 2);
    const rightChild = await this._getNodeHashAsync(level + 1, position * 2 + 1);
    const nodeHash = await poseidonHash([leftChild, rightChild]);
    this.nodes.set(nodeKey, nodeHash);
    return nodeHash;
  }

  /**
   * Calculate the hash of a node (sync version)
   * @param {number} level - Level in the tree (0 = root)
   * @param {number} position - Position in the level
   * @returns {string} Hash of the node
   * @private
   */
  _getNodeHash(level, position) {
    const nodeKey = `${level}-${position}`;
    if (this.nodes.has(nodeKey)) return this.nodes.get(nodeKey);
    if (level === this.depth - 1) {
      const leafValue = this.leaves.has(position) ? this.leaves.get(position) : this.defaultLeafValue;
      return leafValue;
    }
    if (this.zeroHashOptimization) {
      const leftChildKey = `${level + 1}-${position * 2}`;
      const rightChildKey = `${level + 1}-${position * 2 + 1}`;
      const leftEmpty = !this.nodes.has(leftChildKey) && !this._hasLeafInSubtree(level + 1, position * 2);
      const rightEmpty = !this.nodes.has(rightChildKey) && !this._hasLeafInSubtree(level + 1, position * 2 + 1);
      if (leftEmpty && rightEmpty) return this.zeroHashes[level];
    }
    const leftChild = this._getNodeHash(level + 1, position * 2);
    const rightChild = this._getNodeHash(level + 1, position * 2 + 1);
    const nodeHash = poseidonHashSync([leftChild, rightChild]);
    this.nodes.set(nodeKey, nodeHash);
    return nodeHash;
  }

  /**
   * Precompute zero hashes for empty subtrees
   * @private
   */
  _precomputeZeroHashes() {
    let currentZeroHash = this.defaultLeafValue;
    this.zeroHashes = [currentZeroHash];
    for (let i = 0; i < this.depth; i++) {
      currentZeroHash = poseidonHashSync([currentZeroHash, currentZeroHash]);
      this.zeroHashes.unshift(currentZeroHash);
    }
    logger.debug('Precomputed zero hashes for Merkle tree optimization');
  }

  /**
   * Check if a subtree contains any leaves
   * @param {number} level - Level in the tree
   * @param {number} position - Position in the level
   * @returns {boolean} Whether the subtree contains any leaves
   * @private
   */
  _hasLeafInSubtree(level, position) {
    if (level === this.depth - 1) return this.leaves.has(position);
    const startPosition = position * Math.pow(2, this.depth - 1 - level);
    const endPosition = (position + 1) * Math.pow(2, this.depth - 1 - level) - 1;
    for (const leafPosition of this.leaves.keys()) {
      const numericPosition = Number(leafPosition);
      if (numericPosition >= startPosition && numericPosition <= endPosition) return true;
    }
    return false;
  }

  /**
   * Clear nodes affected by a leaf update
   * @param {number|string} leafIndex - Index of the leaf
   * @private
   */
  _clearAffectedNodes(leafIndex) {
    const numericIndex = Number(leafIndex);
    let currentIndex = numericIndex;
    for (let level = this.depth - 1; level >= 0; level--) {
      const nodeKey = `${level}-${currentIndex}`;
      this.nodes.delete(nodeKey);
      currentIndex = Math.floor(currentIndex / 2);
    }
  }

  /**
   * Get binary position of an index
   * @param {number|string} index - Index of the leaf
   * @returns {string} Binary representation of the index
   * @private
   */
  _getPositionBinary(index) {
    if (typeof index === 'string' && /^\d+$/.test(index)) {
      return BigNumber.from(index).toString(2).padStart(this.depth, '0');
    } else if (typeof index === 'number') {
      return index.toString(2).padStart(this.depth, '0');
    } else {
      const hashedKey = BigNumber.from(keccak256Hash(index));
      return hashedKey.mod(BigNumber.from(2).pow(this.depth)).toString(2).padStart(this.depth, '0');
    }
  }
}

/**
 * SparseMerkleTree class optimized for sparse data
 * More efficient for trees with many empty leaves
 * @class SparseMerkleTree
 */
class SparseMerkleTree {
  /**
   * Create a new Sparse Merkle Tree
   * @param {Object} options - Configuration options
   * @param {number} [options.depth=32] - Depth of the tree
   * @param {Function} [options.hashFunction=poseidonHashSync] - Hash function to use
   * @param {string} [options.defaultLeafValue='0'] - Default value for empty leaves
   * @throws {Error} If options are invalid
   */
  constructor({
    depth = 32,
    hashFunction = poseidonHashSync,
    defaultLeafValue = '0'
  } = {}) {
    if (typeof depth !== 'number' || depth <= 0) throw new Error('Depth must be a positive number');
    if (typeof hashFunction !== 'function') throw new Error('hashFunction must be a function');
    if (typeof defaultLeafValue !== 'string') throw new Error('defaultLeafValue must be a string');

    this.depth = depth;
    this.hashFunction = hashFunction;
    this.defaultLeafValue = defaultLeafValue;
    
    // Initialize the tree
    this.nodes = new Map(); // Maps position to node hash
    this.defaultNodes = []; // Precomputed default nodes for each level
    
    // Precompute default nodes
    this._precomputeDefaultNodes();
    
    logger.info(`Initialized Sparse Merkle Tree with depth ${depth}`);
  }

  /**
   * Add or update a leaf in the tree
   * @param {string|number} key - Key for the leaf
   * @param {string} value - Value to store
   * @returns {Promise<void>}
   * @throws {Error} If key or value is invalid
   */
  async update(key, value) {
    if (typeof key !== 'string' && typeof key !== 'number') throw new Error('Key must be a string or number');
    if (typeof value !== 'string') throw new Error('Value must be a string');
    
    const path = this._keyToPath(key);
    await this._update(path, 0, value);
    
    logger.debug(`Updated leaf with key ${key}`);
  }

  /**
   * Get the Merkle root of the tree
   * @returns {Promise<string>} The Merkle root
   */
  async getRoot() {
    return this._getNode([], 0);
  }

  /**
   * Get a Merkle proof for a leaf
   * @param {string|number} key - Key for the leaf
   * @returns {Promise<Object>} Merkle proof
   * @throws {Error} If key is invalid
   */
  async getProof(key) {
    if (typeof key !== 'string' && typeof key !== 'number') throw new Error('Key must be a string or number');
    
    const path = this._keyToPath(key);
    const siblings = [];
    for (let i = 0; i < this.depth; i++) {
      const siblingPath = [...path.slice(0, i), 1 - path[i], ...Array(this.depth - i - 1).fill(0)];
      const siblingNode = await this._getNode(siblingPath, i + 1);
      siblings.push(siblingNode);
    }
    
    const value = await this._getNode(path, this.depth);
    const root = await this.getRoot();
    
    return {
      key,
      value,
      siblings,
      path: path.map(Number),
      root
    };
  }

  /**
   * Verify a Merkle proof
   * @param {Object} proof - The Merkle proof
   * @param {string|number} proof.key - Key of the leaf
   * @param {string} proof.value - Value of the leaf
   * @param {Array<string>} proof.siblings - Sibling nodes along the path
   * @param {Array<number>} proof.path - Binary path to the leaf
   * @param {string} proof.root - Expected Merkle root
   * @returns {Promise<boolean>} Whether the proof is valid
   */
  async verifyProof(proof) {
    const { key, value, siblings, path, root } = proof;
    
    const expectedPath = this._keyToPath(key);
    if (!this._pathsEqual(path, expectedPath)) {
      return false;
    }
    
    let currentNode = value;
    for (let i = this.depth - 1; i >= 0; i--) {
      const isRightChild = path[i] === 1;
      const left = isRightChild ? siblings[i] : currentNode;
      const right = isRightChild ? currentNode : siblings[i];
      currentNode = await poseidonHash([left, right]);
    }
    
    return currentNode === root;
  }

  /**
   * Internal method to update a node
   * @param {Array<number>} path - Path to the node
   * @param {number} level - Current level in the tree
   * @param {string} value - Value to store
   * @returns {Promise<string>} Hash of the updated node
   * @private
   */
  async _update(path, level, value) {
    if (level === this.depth) {
      const nodeKey = this._pathToNodeKey(path, level);
      this.nodes.set(nodeKey, value);
      return value;
    }
    
    const bit = path[level];
    const leftPath = [...path.slice(0, level), 0, ...path.slice(level + 1)];
    const rightPath = [...path.slice(0, level), 1, ...path.slice(level + 1)];
    
    let leftChild, rightChild;
    if (bit === 0) {
      leftChild = await this._update(leftPath, level + 1, value);
      rightChild = await this._getNode(rightPath, level + 1);
    } else {
      leftChild = await this._getNode(leftPath, level + 1);
      rightChild = await this._update(rightPath, level + 1, value);
    }
    
    const nodeHash = await poseidonHash([leftChild, rightChild]);
    const nodeKey = this._pathToNodeKey(path, level);
    this.nodes.set(nodeKey, nodeHash);
    
    return nodeHash;
  }

  /**
   * Get a node's hash
   * @param {Array<number>} path - Path to the node
   * @param {number} level - Current level in the tree
   * @returns {Promise<string>} Hash of the node
   * @private
   */
  async _getNode(path, level) {
    const nodeKey = this._pathToNodeKey(path, level);
    if (this.nodes.has(nodeKey)) {
      return this.nodes.get(nodeKey);
    }
    
    if (level >= this.depth) {
      return this.defaultNodes[this.depth];
    }
    
    const leftPath = [...path.slice(0, level), 0, ...path.slice(level + 1)];
    const rightPath = [...path.slice(0, level), 1, ...path.slice(level + 1)];
    
    const leftChild = await this._getNode(leftPath, level + 1);
    const rightChild = await this._getNode(rightPath, level + 1);
    
    const nodeHash = await poseidonHash([leftChild, rightChild]);
    this.nodes.set(nodeKey, nodeHash);
    
    return nodeHash;
  }

  /**
   * Precompute default nodes for empty subtrees
   * @private
   */
  _precomputeDefaultNodes() {
    this.defaultNodes = Array(this.depth + 1).fill(null);
    this.defaultNodes[this.depth] = this.defaultLeafValue;
    
    for (let i = this.depth - 1; i >= 0; i--) {
      this.defaultNodes[i] = poseidonHashSync([this.defaultNodes[i + 1], this.defaultNodes[i + 1]]);
    }
    
    logger.debug('Precomputed default nodes for Sparse Merkle Tree');
  }

  /**
   * Convert a key to a binary path
   * @param {string|number} key - Key to convert
   * @returns {Array<number>} Binary path (array of 0s and 1s)
   * @private
   */
  _keyToPath(key) {
    const keyHash = BigNumber.from(keccak256Hash(key.toString()));
    const binaryStr = keyHash.mod(BigNumber.from(2).pow(this.depth)).toString(2).padStart(this.depth, '0');
    return Array.from(binaryStr).map(Number);
  }

  /**
   * Convert a path to a node key for caching
   * @param {Array<number>} path - Path to the node
   * @param {number} level - Level in the tree
   * @returns {string} Node key
   * @private
   */
  _pathToNodeKey(path, level) {
    return `${level}:${path.slice(0, level).join('')}`;
  }

  /**
   * Compare two paths for equality
   * @param {Array<number>} path1 - First path
   * @param {Array<number>} path2 - Second path
   * @returns {boolean} Whether the paths are equal
   * @private
   */
  _pathsEqual(path1, path2) {
    if (path1.length !== path2.length) return false;
    for (let i = 0; i < path1.length; i++) {
      if (path1[i] !== path2[i]) return false;
    }
    return true;
  }
}

/**
 * Utility functions for Merkle proofs in Solidity contracts
 */
const MerkleProofUtils = {
  /**
   * Convert a Merkle proof to Solidity-compatible format
   * @param {Object} proof - Merkle proof
   * @returns {Object} Solidity-compatible proof
   * @throws {Error} If proof is invalid
   */
  formatForSolidity(proof) {
    if (!proof || !proof.leaf || !proof.path || !proof.indices || !proof.root) {
      throw new Error('Invalid proof structure for Solidity formatting');
    }
    return {
      leaf: proof.leaf,
      path: proof.path,
      pathIndices: proof.indices.map(Number),
      root: proof.root
    };
  },

  /**
   * Generate a Solidity verifier contract for Merkle proofs
   * @param {number} depth - Tree depth
   * @returns {string} Solidity contract code
   * @throws {Error} If depth is invalid
   */
  generateSolidityVerifier(depth) {
    if (typeof depth !== 'number' || depth <= 0) throw new Error('Depth must be a positive number');
    return `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MerkleVerifier
 * @dev Verifies Merkle proofs of inclusion for the PrivaSight platform
 */
contract MerkleVerifier {
    /**
     * @dev Verifies a Merkle proof proving the existence of a leaf in a Merkle tree.
     * @param leaf Leaf data
     * @param path Array of sibling nodes along the path
     * @param pathIndices Array of indices (0 for left, 1 for right) to indicate position in path
     * @param root Merkle root
     * @return True if proof is valid, false otherwise
     */
    function verifyProof(
        bytes32 leaf,
        bytes32[] memory path,
        uint8[] memory pathIndices,
        bytes32 root
    ) public pure returns (bool) {
        require(path.length == ${depth}, "MerkleVerifier: invalid proof length");
        require(pathIndices.length == ${depth}, "MerkleVerifier: invalid indices length");
        
        bytes32 computedHash = leaf;
        
        for (uint256 i = 0; i < ${depth}; i++) {
            bytes32 proofElement = path[i];
            
            if (pathIndices[i] == 0) {
                // Hash(current proof element + computed hash)
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            } else {
                // Hash(computed hash + current proof element)
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            }
        }
        
        return computedHash == root;
    }
}`;
  }
};

// Export the classes and utilities
module.exports = {
  MerkleTree,
  SparseMerkleTree,
  MerkleProofUtils
};
