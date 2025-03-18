// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

interface IVerifierRegistry {
    function isTrustedVerifier(address verifierAddress, bytes32 proofType) external view returns (bool);
    function findTrustedVerifierForCircuit(bytes32 circuitId) external view returns (address);
    function getCircuitVerificationKey(bytes32 circuitId) external view returns (bytes memory);
}

/**
 * @title Proof Adapter Interface
 * @dev Interface for proof system adapters that can validate ZK proofs.
 */
interface IProofAdapter {
    /**
     * @dev Verify a ZK proof.
     * @param proof The ZK proof
     * @param publicInputs Public inputs for the proof
     * @param verificationKey Verification key for the circuit
     * @param gasLimit Maximum gas to use
     * @return Whether the proof is valid
     */
    function verifyProof(
        bytes memory proof,
        bytes memory publicInputs,
        bytes memory verificationKey,
        uint256 gasLimit
    ) external returns (bool);
    
    /**
     * @dev Verify multiple proofs in a batch.
     * @param proofs Array of ZK proofs
     * @param publicInputsArray Array of public inputs
     * @param verificationKey Verification key for the circuit
     * @param gasLimit Maximum gas to use
     * @return Array of verification results
     */
    function verifyProofBatch(
        bytes[] memory proofs,
        bytes[] memory publicInputsArray,
        bytes memory verificationKey,
        uint256 gasLimit
    ) external returns (bool[] memory);
    
    /**
     * @dev Check if the adapter supports batch verification.
     * @return Whether batch verification is supported
     */
    function supportsBatchVerification() external view returns (bool);
    
    /**
     * @dev Get adapter information.
     * @return name Adapter name
     * @return version Adapter version
     * @return proofSystem Proof system type
     */
    function getAdapterInfo() external view returns (
        string memory name,
        string memory version,
        uint8 proofSystem
    );
}

/**
 * @title PrivaSight Proof Validator
 * @dev Validates and manages Zero-Knowledge Proofs for the PrivaSight ecosystem.
 * Supports multiple proof systems, caching of verification results, batch 
 * verification, and integration with the VerifierRegistry for trusted verifiers.
 */
contract ProofValidator is AccessControl, ReentrancyGuard, Pausable {
    using SafeMath for uint256;

    // ==========================================================================
    // Constants
    // ==========================================================================

    bytes32 public constant VALIDATOR_ADMIN_ROLE = keccak256("VALIDATOR_ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant TRUSTED_CALLER_ROLE = keccak256("TRUSTED_CALLER_ROLE");

    // Proof systems
    uint8 public constant PROOF_SYSTEM_GROTH16 = 1;
    uint8 public constant PROOF_SYSTEM_PLONK = 2;
    uint8 public constant PROOF_SYSTEM_STARK = 3;
    uint8 public constant PROOF_SYSTEM_BULLETPROOFS = 4;
    uint8 public constant PROOF_SYSTEM_CUSTOM = 5;

    // Proof types (mirror those in VerifierRegistry)
    bytes32 public constant PROOF_TYPE_ACCESS = keccak256("ACCESS");
    bytes32 public constant PROOF_TYPE_COMPUTATION = keccak256("COMPUTATION");
    bytes32 public constant PROOF_TYPE_OWNERSHIP = keccak256("OWNERSHIP");
    bytes32 public constant PROOF_TYPE_IDENTITY = keccak256("IDENTITY");
    bytes32 public constant PROOF_TYPE_ATTRIBUTE = keccak256("ATTRIBUTE");
    bytes32 public constant PROOF_TYPE_RANGE = keccak256("RANGE");
    bytes32 public constant PROOF_TYPE_CUSTOM = keccak256("CUSTOM");

    // Validation statuses
    uint8 public constant VALIDATION_STATUS_UNKNOWN = 0;
    uint8 public constant VALIDATION_STATUS_VALID = 1;
    uint8 public constant VALIDATION_STATUS_INVALID = 2;
    uint8 public constant VALIDATION_STATUS_ERROR = 3;

    // ==========================================================================
    // State Variables
    // ==========================================================================

    // External contract references
    IVerifierRegistry public verifierRegistry;

    // Proof validation adapters for different proof systems
    mapping(uint8 => address) public proofAdapters;

    // Proof validation record
    struct ValidationRecord {
        bytes32 proofId;              // Unique ID of the proof
        bytes32 circuitId;            // ID of the circuit used
        address verifier;             // Address of the verifier used
        uint8 proofSystem;            // Type of proof system
        uint8 status;                 // Validation status
        uint256 validationTime;       // When validation was performed
        address validator;            // Who performed the validation
        bytes32 publicInputsHash;     // Hash of the public inputs
        uint256 gasUsed;              // Gas used for validation
        string errorMessage;          // Error message if validation failed
    }

    // Circuit configuration
    struct CircuitConfig {
        bytes32 circuitId;            // ID of the circuit
        uint8 proofSystem;            // Proof system used by this circuit
        uint256 gasLimit;             // Gas limit for validation
        bool cachingEnabled;          // Whether to cache validation results
        uint256 cacheDuration;        // How long to cache results (in seconds)
        bool batchingAllowed;         // Whether this circuit supports batch validation
        uint256 lastUpdateTime;       // When config was last updated
    }

    // Proof adapter interface definition
    struct ProofAdapter {
        address adapterAddress;       // Address of the adapter contract
        uint8 proofSystem;            // Proof system type
        string name;                  // Human-readable name
        string version;               // Semantic version
        bool active;                  // Whether the adapter is active
    }

    // Proof batch record
    struct BatchRecord {
        bytes32 batchId;              // Unique ID of the batch
        bytes32[] proofIds;           // IDs of proofs in the batch
        uint8 status;                 // Batch validation status
        uint256 validationTime;       // When batch validation was performed
        address validator;            // Who performed the validation
        uint256 gasUsed;              // Gas used for batch validation
    }

    // Cache record
    struct CacheRecord {
        bytes32 inputHash;            // Hash of proof and public inputs
        uint8 status;                 // Cached validation status
        uint256 timestamp;            // When the result was cached
        uint256 expiryTime;           // When the cache expires
    }

    // Mappings
    mapping(bytes32 => ValidationRecord) public validations;
    mapping(bytes32 => CircuitConfig) public circuitConfigs;
    mapping(address => ProofAdapter) public proofAdapterInfo;
    mapping(bytes32 => BatchRecord) public batchValidations;
    mapping(bytes32 => CacheRecord) private _validationCache;

    // Indices
    mapping(bytes32 => bytes32[]) private _circuitValidations;
    mapping(address => bytes32[]) private _verifierValidations;
    mapping(uint8 => bytes32[]) private _proofSystemValidations;
    mapping(bytes32 => bytes32[]) private _circuitBatches;

    // Statistics
    uint256 public totalValidations;
    uint256 public validProofs;
    uint256 public invalidProofs;
    uint256 public cacheHits;
    uint256 public cacheMisses;
    uint256 public totalBatches;
    uint256 public totalBatchedProofs;

    // Cache configuration
    uint256 public defaultCacheDuration = 1 days;
    bool public globalCachingEnabled = true;

    // Gas limit protection
    uint256 public maxGasLimit = 10_000_000;

    // Events
    event ProofValidated(
        bytes32 indexed proofId,
        bytes32 indexed circuitId,
        uint8 status,
        address validator,
        uint256 gasUsed
    );

    event BatchValidated(
        bytes32 indexed batchId,
        uint256 proofCount,
        uint8 status,
        address validator,
        uint256 gasUsed
    );

    event CircuitConfigUpdated(
        bytes32 indexed circuitId,
        uint8 proofSystem,
        uint256 gasLimit,
        bool cachingEnabled,
        uint256 cacheDuration,
        bool batchingAllowed
    );

    event ProofAdapterRegistered(
        address indexed adapterAddress,
        uint8 proofSystem,
        string name,
        string version
    );

    event ProofAdapterStatusChanged(
        address indexed adapterAddress,
        bool active
    );

    event CacheHit(
        bytes32 indexed proofId,
        bytes32 inputHash,
        uint8 status
    );

    event CacheMiss(
        bytes32 indexed proofId,
        bytes32 inputHash
    );

    // ==========================================================================
    // Constructor
    // ==========================================================================

    /**
     * @dev Initializes the Proof Validator contract.
     * @param _verifierRegistry Address of the Verifier Registry contract
     */
    constructor(address _verifierRegistry) {
        require(_verifierRegistry != address(0), "Invalid Verifier Registry address");

        verifierRegistry = IVerifierRegistry(_verifierRegistry);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VALIDATOR_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
    }

    // ==========================================================================
    // Proof Validation
    // ==========================================================================

    /**
     * @dev Validate a proof.
     * @param proofId Unique ID of the proof
     * @param circuitId ID of the circuit used
     * @param proof The ZK proof to validate
     * @param publicInputs Public inputs for the proof
     * @return status Validation status
     */
    function validateProof(
        bytes32 proofId,
        bytes32 circuitId,
        bytes memory proof,
        bytes memory publicInputs
    ) 
        external
        whenNotPaused
        nonReentrant
        returns (uint8 status)
    {
        require(
            hasRole(VERIFIER_ROLE, msg.sender) || 
            hasRole(TRUSTED_CALLER_ROLE, msg.sender),
            "Not authorized to validate proofs"
        );

        CircuitConfig storage config = circuitConfigs[circuitId];
        if (config.circuitId == bytes32(0)) {
            config.circuitId = circuitId;
            config.proofSystem = PROOF_SYSTEM_GROTH16;
            config.gasLimit = 2_000_000;
            config.cachingEnabled = globalCachingEnabled;
            config.cacheDuration = defaultCacheDuration;
            config.batchingAllowed = false;
            config.lastUpdateTime = block.timestamp;
        }

        if (validations[proofId].validationTime > 0) {
            return validations[proofId].status;
        }

        if (config.cachingEnabled && globalCachingEnabled) {
            bytes32 inputHash = keccak256(abi.encodePacked(circuitId, proof, publicInputs));
            CacheRecord storage cacheRecord = _validationCache[inputHash];
            
            if (cacheRecord.timestamp > 0 && block.timestamp < cacheRecord.expiryTime) {
                cacheHits++;
                _createValidationRecord(proofId, circuitId, config.proofSystem, cacheRecord.status, keccak256(publicInputs), 0, "");
                emit CacheHit(proofId, inputHash, cacheRecord.status);
                return cacheRecord.status;
            } else if (cacheRecord.timestamp > 0) {
                emit CacheMiss(proofId, inputHash);
                cacheMisses++;
            }
        }

        address adapterAddress = proofAdapters[config.proofSystem];
        require(adapterAddress != address(0), "No adapter for this proof system");
        require(proofAdapterInfo[adapterAddress].active, "Proof adapter is not active");

        bytes memory verificationKey = verifierRegistry.getCircuitVerificationKey(circuitId);
        require(verificationKey.length > 0, "Verification key not found");

        uint256 startGas = gasleft();

        try IProofAdapter(adapterAddress).verifyProof(proof, publicInputs, verificationKey, config.gasLimit) returns (bool valid) {
            uint256 gasUsed = startGas - gasleft();
            status = valid ? VALIDATION_STATUS_VALID : VALIDATION_STATUS_INVALID;
            _createValidationRecord(proofId, circuitId, config.proofSystem, status, keccak256(publicInputs), gasUsed, "");

            if (config.cachingEnabled && globalCachingEnabled) {
                bytes32 inputHash = keccak256(abi.encodePacked(circuitId, proof, publicInputs));
                _validationCache[inputHash] = CacheRecord({
                    inputHash: inputHash,
                    status: status,
                    timestamp: block.timestamp,
                    expiryTime: block.timestamp + config.cacheDuration
                });
            }

            emit ProofValidated(proofId, circuitId, status, msg.sender, gasUsed);
            return status;
        } catch Error(string memory reason) {
            uint256 gasUsed = startGas - gasleft();
            status = VALIDATION_STATUS_ERROR;
            _createValidationRecord(proofId, circuitId, config.proofSystem, status, keccak256(publicInputs), gasUsed, reason);
            emit ProofValidated(proofId, circuitId, status, msg.sender, gasUsed);
            return status;
        }
    }

    /**
     * @dev Validate multiple proofs in a batch.
     * @param batchId Unique ID for the batch
     * @param proofIds Array of proof IDs
     * @param circuitId ID of the circuit (must be the same for all proofs)
     * @param proofs Array of ZK proofs
     * @param publicInputsArray Array of public inputs
     * @return validCount Number of valid proofs
     * @return invalidCount Number of invalid proofs
     * @return errorCount Number of proofs with errors
     */
    function validateProofBatch(
        bytes32 batchId,
        bytes32[] memory proofIds,
        bytes32 circuitId,
        bytes[] memory proofs,
        bytes[] memory publicInputsArray
    ) 
        external
        whenNotPaused
        nonReentrant
        returns (uint256 validCount, uint256 invalidCount, uint256 errorCount)
    {
        require(hasRole(VERIFIER_ROLE, msg.sender) || hasRole(TRUSTED_CALLER_ROLE, msg.sender), "Not authorized to validate proofs");
        require(proofIds.length == proofs.length, "Proof IDs and proofs length mismatch");
        require(proofs.length == publicInputsArray.length, "Proofs and public inputs length mismatch");
        require(proofIds.length > 0, "No proofs provided");

        CircuitConfig storage config = circuitConfigs[circuitId];
        if (config.circuitId == bytes32(0)) {
            config.circuitId = circuitId;
            config.proofSystem = PROOF_SYSTEM_GROTH16;
            config.gasLimit = 2_000_000 * proofIds.length;
            config.cachingEnabled = globalCachingEnabled;
            config.cacheDuration = defaultCacheDuration;
            config.batchingAllowed = true;
            config.lastUpdateTime = block.timestamp;
        }

        require(config.batchingAllowed, "Batching not allowed for this circuit");

        address adapterAddress = proofAdapters[config.proofSystem];
        require(adapterAddress != address(0), "No adapter for this proof system");
        require(proofAdapterInfo[adapterAddress].active, "Proof adapter is not active");

        bytes memory verificationKey = verifierRegistry.getCircuitVerificationKey(circuitId);
        require(verificationKey.length > 0, "Verification key not found");

        uint256 startGas = gasleft();

        BatchRecord storage batch = batchValidations[batchId];
        batch.batchId = batchId;
        batch.proofIds = proofIds;
        batch.validationTime = block.timestamp;
        batch.validator = msg.sender;

        _circuitBatches[circuitId].push(batchId);
        totalBatches++;
        totalBatchedProofs += proofIds.length;

        if (IProofAdapter(adapterAddress).supportsBatchVerification()) {
            try IProofAdapter(adapterAddress).verifyProofBatch(proofs, publicInputsArray, verificationKey, config.gasLimit) returns (bool[] memory results) {
                require(results.length == proofIds.length, "Results length mismatch");
                for (uint256 i = 0; i < proofIds.length; i++) {
                    uint8 status = results[i] ? VALIDATION_STATUS_VALID : VALIDATION_STATUS_INVALID;
                    _createValidationRecord(proofIds[i], circuitId, config.proofSystem, status, keccak256(publicInputsArray[i]), 0, "");
                    if (status == VALIDATION_STATUS_VALID) validCount++;
                    else invalidCount++;
                    if (config.cachingEnabled && globalCachingEnabled) {
                        bytes32 inputHash = keccak256(abi.encodePacked(circuitId, proofs[i], publicInputsArray[i]));
                        _validationCache[inputHash] = CacheRecord(inputHash, status, block.timestamp, block.timestamp + config.cacheDuration);
                    }
                }
            } catch {
                for (uint256 i = 0; i < proofIds.length; i++) {
                    try IProofAdapter(adapterAddress).verifyProof(proofs[i], publicInputsArray[i], verificationKey, config.gasLimit / proofIds.length) returns (bool valid) {
                        uint8 status = valid ? VALIDATION_STATUS_VALID : VALIDATION_STATUS_INVALID;
                        _createValidationRecord(proofIds[i], circuitId, config.proofSystem, status, keccak256(publicInputsArray[i]), 0, "");
                        if (status == VALIDATION_STATUS_VALID) validCount++;
                        else invalidCount++;
                        if (config.cachingEnabled && globalCachingEnabled) {
                            bytes32 inputHash = keccak256(abi.encodePacked(circuitId, proofs[i], publicInputsArray[i]));
                            _validationCache[inputHash] = CacheRecord(inputHash, status, block.timestamp, block.timestamp + config.cacheDuration);
                        }
                    } catch {
                        uint8 status = VALIDATION_STATUS_ERROR;
                        _createValidationRecord(proofIds[i], circuitId, config.proofSystem, status, keccak256(publicInputsArray[i]), 0, "Verification error");
                        errorCount++;
                    }
                }
            }
        } else {
            for (uint256 i = 0; i < proofIds.length; i++) {
                try IProofAdapter(adapterAddress).verifyProof(proofs[i], publicInputsArray[i], verificationKey, config.gasLimit / proofIds.length) returns (bool valid) {
                    uint8 status = valid ? VALIDATION_STATUS_VALID : VALIDATION_STATUS_INVALID;
                    _createValidationRecord(proofIds[i], circuitId, config.proofSystem, status, keccak256(publicInputsArray[i]), 0, "");
                    if (status == VALIDATION_STATUS_VALID) validCount++;
                    else invalidCount++;
                    if (config.cachingEnabled && globalCachingEnabled) {
                        bytes32 inputHash = keccak256(abi.encodePacked(circuitId, proofs[i], publicInputsArray[i]));
                        _validationCache[inputHash] = CacheRecord(inputHash, status, block.timestamp, block.timestamp + config.cacheDuration);
                    }
                } catch {
                    uint8 status = VALIDATION_STATUS_ERROR;
                    _createValidationRecord(proofIds[i], circuitId, config.proofSystem, status, keccak256(publicInputsArray[i]), 0, "Verification error");
                    errorCount++;
                }
            }
        }

        uint256 gasUsed = startGas - gasleft();
        batch.status = (validCount == proofIds.length) ? VALIDATION_STATUS_VALID : ((errorCount > 0) ? VALIDATION_STATUS_ERROR : VALIDATION_STATUS_INVALID);
        batch.gasUsed = gasUsed;

        if (validCount > 0) validProofs += validCount;
        if (invalidCount > 0) invalidProofs += invalidCount;
        totalValidations += proofIds.length;

        emit BatchValidated(batchId, proofIds.length, batch.status, msg.sender, gasUsed);
        return (validCount, invalidCount, errorCount);
    }

    /**
     * @dev Create a validation record.
     * @param proofId Unique ID of the proof
     * @param circuitId ID of the circuit used
     * @param proofSystem Type of proof system
     * @param status Validation status
     * @param publicInputsHash Hash of the public inputs
     * @param gasUsed Gas used for validation
     * @param errorMessage Error message if validation failed
     */
    function _createValidationRecord(
        bytes32 proofId,
        bytes32 circuitId,
        uint8 proofSystem,
        uint8 status,
        bytes32 publicInputsHash,
        uint256 gasUsed,
        string memory errorMessage
    ) internal {
        address verifier = verifierRegistry.findTrustedVerifierForCircuit(circuitId);
        ValidationRecord storage record = validations[proofId];
        record.proofId = proofId;
        record.circuitId = circuitId;
        record.verifier = verifier;
        record.proofSystem = proofSystem;
        record.status = status;
        record.validationTime = block.timestamp;
        record.validator = msg.sender;
        record.publicInputsHash = publicInputsHash;
        record.gasUsed = gasUsed;
        record.errorMessage = errorMessage;

        _circuitValidations[circuitId].push(proofId);
        if (verifier != address(0)) _verifierValidations[verifier].push(proofId);
        _proofSystemValidations[proofSystem].push(proofId);

        totalValidations++;
        if (status == VALIDATION_STATUS_VALID) validProofs++;
        else if (status == VALIDATION_STATUS_INVALID) invalidProofs++;
    }

    /**
     * @dev Check if a proof is valid.
     * @param proofId Unique ID of the proof
     * @return valid Whether the proof is valid
     * @return status The validation status
     */
    function isProofValid(bytes32 proofId) external view returns (bool valid, uint8 status) {
        ValidationRecord storage record = validations[proofId];
        if (record.validationTime == 0) return (false, VALIDATION_STATUS_UNKNOWN);
        return (record.status == VALIDATION_STATUS_VALID, record.status);
    }

    /**
     * @dev Get validation record details.
     * @param proofId Unique ID of the proof
     */
    function getValidationRecord(bytes32 proofId) 
        external view returns (
            bytes32 circuitId,
            address verifier,
            uint8 proofSystem,
            uint8 status,
            uint256 validationTime,
            address validator,
            bytes32 publicInputsHash,
            uint256 gasUsed,
            string memory errorMessage
        ) {
        ValidationRecord storage record = validations[proofId];
        require(record.validationTime > 0, "Validation record not found");
        return (
            record.circuitId,
            record.verifier,
            record.proofSystem,
            record.status,
            record.validationTime,
            record.validator,
            record.publicInputsHash,
            record.gasUsed,
            record.errorMessage
        );
    }

    function getCircuitValidations(bytes32 circuitId) external view returns (bytes32[] memory) {
        return _circuitValidations[circuitId];
    }

    function getVerifierValidations(address verifier) external view returns (bytes32[] memory) {
        return _verifierValidations[verifier];
    }

    function getProofSystemValidations(uint8 proofSystem) external view returns (bytes32[] memory) {
        return _proofSystemValidations[proofSystem];
    }

    function getCircuitBatches(bytes32 circuitId) external view returns (bytes32[] memory) {
        return _circuitBatches[circuitId];
    }

    // ==========================================================================
    // Circuit Configuration
    // ==========================================================================

    function setCircuitConfig(
        bytes32 circuitId,
        uint8 proofSystem,
        uint256 gasLimit,
        bool cachingEnabled,
        uint256 cacheDuration,
        bool batchingAllowed
    ) external onlyRole(VALIDATOR_ADMIN_ROLE) whenNotPaused {
        require(proofSystem >= PROOF_SYSTEM_GROTH16 && proofSystem <= PROOF_SYSTEM_CUSTOM, "Invalid proof system");
        require(gasLimit <= maxGasLimit, "Gas limit exceeds maximum");
        require(proofAdapters[proofSystem] != address(0), "No adapter for this proof system");

        CircuitConfig storage config = circuitConfigs[circuitId];
        config.circuitId = circuitId;
        config.proofSystem = proofSystem;
        config.gasLimit = gasLimit;
        config.cachingEnabled = cachingEnabled;
        config.cacheDuration = cacheDuration;
        config.batchingAllowed = batchingAllowed;
        config.lastUpdateTime = block.timestamp;

        emit CircuitConfigUpdated(circuitId, proofSystem, gasLimit, cachingEnabled, cacheDuration, batchingAllowed);
    }

    function getCircuitConfig(bytes32 circuitId) 
        external view returns (
            uint8 proofSystem,
            uint256 gasLimit,
            bool cachingEnabled,
            uint256 cacheDuration,
            bool batchingAllowed,
            uint256 lastUpdateTime
        ) {
        CircuitConfig storage config = circuitConfigs[circuitId];
        if (config.circuitId == bytes32(0)) {
            return (PROOF_SYSTEM_GROTH16, 2_000_000, globalCachingEnabled, defaultCacheDuration, false, 0);
        }
        return (config.proofSystem, config.gasLimit, config.cachingEnabled, config.cacheDuration, config.batchingAllowed, config.lastUpdateTime);
    }

    // ==========================================================================
    // Proof Adapter Management
    // ==========================================================================

    function registerProofAdapter(address adapterAddress, uint8 proofSystem, string memory name, string memory version) 
        external onlyRole(VALIDATOR_ADMIN_ROLE) whenNotPaused {
        require(adapterAddress != address(0), "Invalid adapter address");
        require(proofSystem >= PROOF_SYSTEM_GROTH16 && proofSystem <= PROOF_SYSTEM_CUSTOM, "Invalid proof system");
        require(bytes(name).length > 0, "Name cannot be empty");
        require(bytes(version).length > 0, "Version cannot be empty");
        require(adapterAddress.code.length > 0, "Adapter must be a contract");

        proofAdapters[proofSystem] = adapterAddress;
        proofAdapterInfo[adapterAddress] = ProofAdapter(adapterAddress, proofSystem, name, version, true);
        emit ProofAdapterRegistered(adapterAddress, proofSystem, name, version);
    }

    function updateProofAdapterStatus(address adapterAddress, bool active) external onlyRole(VALIDATOR_ADMIN_ROLE) whenNotPaused {
        require(proofAdapterInfo[adapterAddress].adapterAddress != address(0), "Adapter not registered");
        proofAdapterInfo[adapterAddress].active = active;
        emit ProofAdapterStatusChanged(adapterAddress, active);
    }

    function setMaxGasLimit(uint256 newMaxGasLimit) external onlyRole(VALIDATOR_ADMIN_ROLE) {
        maxGasLimit = newMaxGasLimit;
    }

    // ==========================================================================
    // Cache Management
    // ==========================================================================

    function setGlobalCachingEnabled(bool enabled) external onlyRole(VALIDATOR_ADMIN_ROLE) {
        globalCachingEnabled = enabled;
    }

    function setDefaultCacheDuration(uint256 duration) external onlyRole(VALIDATOR_ADMIN_ROLE) {
        defaultCacheDuration = duration;
    }

    function clearCacheEntry(bytes32 inputHash) external onlyRole(VALIDATOR_ADMIN_ROLE) {
        delete _validationCache[inputHash];
    }

    function checkCache(bytes32 inputHash) external view returns (bool cached, uint8 status, uint256 timestamp, uint256 expiryTime) {
        CacheRecord storage record = _validationCache[inputHash];
        if (record.timestamp == 0) return (false, 0, 0, 0);
        return (true, record.status, record.timestamp, record.expiryTime);
    }

    // ==========================================================================
    // Statistics and Information
    // ==========================================================================

    function getValidationStats() external view returns (
        uint256 total,
        uint256 valid,
        uint256 invalid,
        uint256 cacheHit,
        uint256 cacheMiss,
        uint256 batches,
        uint256 batchedProofs
    ) {
        return (totalValidations, validProofs, invalidProofs, cacheHits, cacheMisses, totalBatches, totalBatchedProofs);
    }

    // ==========================================================================
    // Admin Functions
    // ==========================================================================

    function setVerifierRegistry(address _verifierRegistry) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_verifierRegistry != address(0), "Invalid Verifier Registry address");
        verifierRegistry = IVerifierRegistry(_verifierRegistry);
    }

    function addTrustedCaller(address caller) external onlyRole(VALIDATOR_ADMIN_ROLE) {
        _grantRole(TRUSTED_CALLER_ROLE, caller);
    }

    function removeTrustedCaller(address caller) external onlyRole(VALIDATOR_ADMIN_ROLE) {
        _revokeRole(TRUSTED_CALLER_ROLE, caller);
    }

    function pause() external onlyRole(VALIDATOR_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(VALIDATOR_ADMIN_ROLE) {
        _unpause();
    }
}
