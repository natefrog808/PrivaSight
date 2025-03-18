// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts/utils/Address.sol";

/**
 * @title PrivaSight Verifier Registry
 * @dev Registry for ZKP verifiers in the PrivaSight ecosystem.
 * This contract manages the registration, verification, and status tracking of
 * zero-knowledge proof verifiers for different proof types and circuits.
 */
contract VerifierRegistry is AccessControl, ReentrancyGuard, Pausable {
    using SafeMath for uint256;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using Address for address;

    // ==========================================================================
    // Constants
    // ==========================================================================

    /** @dev Role for registry administrators */
    bytes32 public constant REGISTRY_ADMIN_ROLE = keccak256("REGISTRY_ADMIN_ROLE");
    /** @dev Role for circuit managers */
    bytes32 public constant CIRCUIT_MANAGER_ROLE = keccak256("CIRCUIT_MANAGER_ROLE");
    /** @dev Role for verifier managers */
    bytes32 public constant VERIFIER_MANAGER_ROLE = keccak256("VERIFIER_MANAGER_ROLE");
    /** @dev Role for trusted forwarders (meta-transactions) */
    bytes32 public constant TRUSTED_FORWARDER_ROLE = keccak256("TRUSTED_FORWARDER_ROLE");

    // Verifier status constants
    uint8 public constant VERIFIER_STATUS_INACTIVE = 0;
    uint8 public constant VERIFIER_STATUS_ACTIVE = 1;
    uint8 public constant VERIFIER_STATUS_DEPRECATED = 2;
    uint8 public constant VERIFIER_STATUS_REVOKED = 3;

    // Circuit status constants
    uint8 public constant CIRCUIT_STATUS_DRAFT = 0;
    uint8 public constant CIRCUIT_STATUS_ACTIVE = 1;
    uint8 public constant CIRCUIT_STATUS_DEPRECATED = 2;
    uint8 public constant CIRCUIT_STATUS_REVOKED = 3;

    // Predefined proof type constants
    bytes32 public constant PROOF_TYPE_ACCESS = keccak256("ACCESS");
    bytes32 public constant PROOF_TYPE_COMPUTATION = keccak256("COMPUTATION");
    bytes32 public constant PROOF_TYPE_OWNERSHIP = keccak256("OWNERSHIP");
    bytes32 public constant PROOF_TYPE_IDENTITY = keccak256("IDENTITY");
    bytes32 public constant PROOF_TYPE_ATTRIBUTE = keccak256("ATTRIBUTE");
    bytes32 public constant PROOF_TYPE_RANGE = keccak256("RANGE");
    bytes32 public constant PROOF_TYPE_CUSTOM = keccak256("CUSTOM");

    // ==========================================================================
    // State Variables
    // ==========================================================================

    /** @dev Struct to store verifier information */
    struct Verifier {
        address verifierAddress;      // Contract address of the verifier
        bytes32 proofType;            // Type of proof this verifier handles
        string description;           // Description of the verifier
        string version;               // Semantic version of the verifier
        uint8 status;                 // Current status
        uint256 registrationTime;     // When the verifier was registered
        uint256 lastUpdateTime;       // When the verifier was last updated
        address registeredBy;         // Who registered this verifier
        bytes32[] supportedCircuits;  // List of circuit IDs this verifier supports
        string metadataURI;           // URI to additional metadata (e.g., IPFS hash)
    }

    /** @dev Struct to store circuit information */
    struct Circuit {
        bytes32 circuitId;            // Unique ID of the circuit
        bytes32 proofType;            // Type of proof this circuit is for
        string name;                  // Human-readable name
        string description;           // Description of the circuit
        string version;               // Semantic version
        uint8 status;                 // Current status
        uint256 creationTime;         // When the circuit was created
        uint256 lastUpdateTime;       // When the circuit was last updated
        address createdBy;            // Who created this circuit
        bytes verificationKey;        // Verification key for the circuit
        string metadataURI;           // URI to additional metadata
    }

    /** @dev Struct to store proof verification results */
    struct VerificationResult {
        bytes32 proofId;              // Unique ID of the proof
        bytes32 circuitId;            // ID of the circuit used
        address verifier;             // Address of the verifier used
        bool valid;                   // Whether the proof was valid
        uint256 verificationTime;     // When the verification was performed
        bytes32 publicInputsHash;     // Hash of the public inputs
        address verifiedFor;          // Address the proof was verified for
        uint256 gasUsed;              // Gas used for verification
    }

    // Mapping of proof types to their trusted verifiers
    mapping(bytes32 => EnumerableSet.AddressSet) private _trustedVerifiers;

    // Mapping of verifier addresses to their details
    mapping(address => Verifier) public verifiers;

    // Set of all registered verifier addresses
    EnumerableSet.AddressSet private _allVerifiers;

    // Mapping of circuit IDs to their details
    mapping(bytes32 => Circuit) public circuits;

    // Set of all registered circuit IDs
    EnumerableSet.Bytes32Set private _allCircuits;

    // Mapping of proof IDs to their verification results
    mapping(bytes32 => VerificationResult) public verificationResults;

    // Mapping to find circuit IDs by proof type and name
    mapping(bytes32 => mapping(string => bytes32)) private _circuitByTypeAndName;

    // Set of supported proof types
    EnumerableSet.Bytes32Set private _supportedProofTypes;

    // Verification statistics
    uint256 public totalVerifications;
    uint256 public successfulVerifications;
    uint256 public failedVerifications;

    // Gas usage statistics
    uint256 public totalGasUsed;
    uint256 public averageGasUsed;

    // ==========================================================================
    // Events
    // ==========================================================================

    event VerifierRegistered(address indexed verifierAddress, bytes32 indexed proofType, string version, address registeredBy);
    event VerifierStatusChanged(address indexed verifierAddress, uint8 oldStatus, uint8 newStatus);
    event VerifierCircuitSupport(address indexed verifierAddress, bytes32 indexed circuitId, bool added);
    event CircuitRegistered(bytes32 indexed circuitId, bytes32 indexed proofType, string name, string version, address createdBy);
    event CircuitStatusChanged(bytes32 indexed circuitId, uint8 oldStatus, uint8 newStatus);
    event CircuitVerificationKeyUpdated(bytes32 indexed circuitId, address updatedBy);
    event ProofTypeAdded(bytes32 indexed proofType, string name);
    event ProofVerified(bytes32 indexed proofId, bytes32 indexed circuitId, address indexed verifier, bool valid);

    // ==========================================================================
    // Constructor
    // ==========================================================================

    /**
     * @dev Initializes the Verifier Registry contract, setting up roles and predefined proof types.
     */
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_ADMIN_ROLE, msg.sender);
        _grantRole(CIRCUIT_MANAGER_ROLE, msg.sender);
        _grantRole(VERIFIER_MANAGER_ROLE, msg.sender);

        // Initialize supported proof types
        _supportedProofTypes.add(PROOF_TYPE_ACCESS);
        _supportedProofTypes.add(PROOF_TYPE_COMPUTATION);
        _supportedProofTypes.add(PROOF_TYPE_OWNERSHIP);
        _supportedProofTypes.add(PROOF_TYPE_IDENTITY);
        _supportedProofTypes.add(PROOF_TYPE_ATTRIBUTE);
        _supportedProofTypes.add(PROOF_TYPE_RANGE);
        _supportedProofTypes.add(PROOF_TYPE_CUSTOM);
    }

    // ==========================================================================
    // Verifier Management
    // ==========================================================================

    /**
     * @dev Registers a new verifier with the specified details.
     * @param verifierAddress Address of the verifier contract
     * @param proofType Type of proof this verifier handles
     * @param description Description of the verifier
     * @param version Semantic version of the verifier
     * @param metadataURI URI to additional metadata
     */
    function registerVerifier(
        address verifierAddress,
        bytes32 proofType,
        string memory description,
        string memory version,
        string memory metadataURI
    ) external onlyRole(VERIFIER_MANAGER_ROLE) whenNotPaused {
        require(verifierAddress != address(0), "Invalid verifier address");
        require(proofType != bytes32(0), "Invalid proof type");
        require(_supportedProofTypes.contains(proofType), "Unsupported proof type");
        require(verifierAddress.isContract(), "Verifier must be a contract");
        require(bytes(version).length > 0, "Version cannot be empty");
        require(!_allVerifiers.contains(verifierAddress), "Verifier already registered");

        Verifier storage verifier = verifiers[verifierAddress];
        verifier.verifierAddress = verifierAddress;
        verifier.proofType = proofType;
        verifier.description = description;
        verifier.version = version;
        verifier.status = VERIFIER_STATUS_ACTIVE;
        verifier.registrationTime = block.timestamp;
        verifier.lastUpdateTime = block.timestamp;
        verifier.registeredBy = msg.sender;
        verifier.metadataURI = metadataURI;

        _allVerifiers.add(verifierAddress);
        _trustedVerifiers[proofType].add(verifierAddress);

        emit VerifierRegistered(verifierAddress, proofType, version, msg.sender);
    }

    /**
     * @dev Updates the status of an existing verifier.
     * @param verifierAddress Address of the verifier
     * @param newStatus New status to set
     */
    function updateVerifierStatus(
        address verifierAddress,
        uint8 newStatus
    ) external onlyRole(VERIFIER_MANAGER_ROLE) whenNotPaused {
        require(_allVerifiers.contains(verifierAddress), "Verifier not registered");
        require(newStatus <= VERIFIER_STATUS_REVOKED, "Invalid status");

        Verifier storage verifier = verifiers[verifierAddress];
        uint8 oldStatus = verifier.status;
        require(oldStatus != newStatus, "Status already set");

        verifier.status = newStatus;
        verifier.lastUpdateTime = block.timestamp;

        if (newStatus == VERIFIER_STATUS_ACTIVE) {
            _trustedVerifiers[verifier.proofType].add(verifierAddress);
        } else {
            _trustedVerifiers[verifier.proofType].remove(verifierAddress);
        }

        emit VerifierStatusChanged(verifierAddress, oldStatus, newStatus);
    }

    /**
     * @dev Adds support for a circuit to a verifier.
     * @param verifierAddress Address of the verifier
     * @param circuitId ID of the circuit to support
     */
    function addVerifierCircuit(
        address verifierAddress,
        bytes32 circuitId
    ) external onlyRole(VERIFIER_MANAGER_ROLE) whenNotPaused {
        require(_allVerifiers.contains(verifierAddress), "Verifier not registered");
        require(_allCircuits.contains(circuitId), "Circuit not registered");

        Verifier storage verifier = verifiers[verifierAddress];
        Circuit storage circuit = circuits[circuitId];
        require(verifier.proofType == circuit.proofType, "Verifier doesn't support this proof type");

        for (uint256 i = 0; i < verifier.supportedCircuits.length; i++) {
            require(verifier.supportedCircuits[i] != circuitId, "Verifier already supports this circuit");
        }

        verifier.supportedCircuits.push(circuitId);
        verifier.lastUpdateTime = block.timestamp;

        emit VerifierCircuitSupport(verifierAddress, circuitId, true);
    }

    /**
     * @dev Removes support for a circuit from a verifier.
     * @param verifierAddress Address of the verifier
     * @param circuitId ID of the circuit to remove
     */
    function removeVerifierCircuit(
        address verifierAddress,
        bytes32 circuitId
    ) external onlyRole(VERIFIER_MANAGER_ROLE) whenNotPaused {
        require(_allVerifiers.contains(verifierAddress), "Verifier not registered");

        Verifier storage verifier = verifiers[verifierAddress];
        bool found = false;
        uint256 index;

        for (uint256 i = 0; i < verifier.supportedCircuits.length; i++) {
            if (verifier.supportedCircuits[i] == circuitId) {
                found = true;
                index = i;
                break;
            }
        }
        require(found, "Verifier doesn't support this circuit");

        verifier.supportedCircuits[index] = verifier.supportedCircuits[verifier.supportedCircuits.length - 1];
        verifier.supportedCircuits.pop();
        verifier.lastUpdateTime = block.timestamp;

        emit VerifierCircuitSupport(verifierAddress, circuitId, false);
    }

    /**
     * @dev Updates the metadata of a verifier.
     * @param verifierAddress Address of the verifier
     * @param description New description
     * @param version New version
     * @param metadataURI New metadata URI
     */
    function updateVerifierMetadata(
        address verifierAddress,
        string memory description,
        string memory version,
        string memory metadataURI
    ) external onlyRole(VERIFIER_MANAGER_ROLE) whenNotPaused {
        require(_allVerifiers.contains(verifierAddress), "Verifier not registered");
        require(bytes(version).length > 0, "Version cannot be empty");

        Verifier storage verifier = verifiers[verifierAddress];
        verifier.description = description;
        verifier.version = version;
        verifier.metadataURI = metadataURI;
        verifier.lastUpdateTime = block.timestamp;
    }

    /**
     * @dev Retrieves detailed information about a verifier.
     * @param verifierAddress Address of the verifier
     * @return proofType, description, version, status, registrationTime, lastUpdateTime, registeredBy, supportedCircuits, metadataURI
     */
    function getVerifierDetails(address verifierAddress)
        external
        view
        returns (
            bytes32 proofType,
            string memory description,
            string memory version,
            uint8 status,
            uint256 registrationTime,
            uint256 lastUpdateTime,
            address registeredBy,
            bytes32[] memory supportedCircuits,
            string memory metadataURI
        )
    {
        require(_allVerifiers.contains(verifierAddress), "Verifier not registered");
        Verifier storage verifier = verifiers[verifierAddress];
        return (
            verifier.proofType,
            verifier.description,
            verifier.version,
            verifier.status,
            verifier.registrationTime,
            verifier.lastUpdateTime,
            verifier.registeredBy,
            verifier.supportedCircuits,
            verifier.metadataURI
        );
    }

    /**
     * @dev Returns all registered verifier addresses.
     * @return Array of verifier addresses
     */
    function getAllVerifiers() external view returns (address[] memory) {
        return _allVerifiers.values();
    }

    /**
     * @dev Returns trusted verifiers for a specific proof type.
     * @param proofType Type of proof
     * @return Array of trusted verifier addresses
     */
    function getTrustedVerifiers(bytes32 proofType) external view returns (address[] memory) {
        return _trustedVerifiers[proofType].values();
    }

    // ==========================================================================
    // Circuit Management
    // ==========================================================================

    /**
     * @dev Registers a new circuit with the specified details.
     * @param proofType Type of proof this circuit is for
     * @param name Human-readable name
     * @param description Description of the circuit
     * @param version Semantic version
     * @param verificationKey Verification key for the circuit
     * @param metadataURI URI to additional metadata
     * @return circuitId ID of the registered circuit
     */
    function registerCircuit(
        bytes32 proofType,
        string memory name,
        string memory description,
        string memory version,
        bytes memory verificationKey,
        string memory metadataURI
    ) external onlyRole(CIRCUIT_MANAGER_ROLE) whenNotPaused returns (bytes32 circuitId) {
        require(proofType != bytes32(0), "Invalid proof type");
        require(_supportedProofTypes.contains(proofType), "Unsupported proof type");
        require(bytes(name).length > 0, "Name cannot be empty");
        require(bytes(version).length > 0, "Version cannot be empty");
        require(verificationKey.length > 0, "Verification key cannot be empty");

        circuitId = keccak256(abi.encodePacked(proofType, name, version));
        require(!_allCircuits.contains(circuitId), "Circuit already exists");

        Circuit storage circuit = circuits[circuitId];
        circuit.circuitId = circuitId;
        circuit.proofType = proofType;
        circuit.name = name;
        circuit.description = description;
        circuit.version = version;
        circuit.status = CIRCUIT_STATUS_ACTIVE;
        circuit.creationTime = block.timestamp;
        circuit.lastUpdateTime = block.timestamp;
        circuit.createdBy = msg.sender;
        circuit.verificationKey = verificationKey;
        circuit.metadataURI = metadataURI;

        _allCircuits.add(circuitId);
        _circuitByTypeAndName[proofType][name] = circuitId;

        emit CircuitRegistered(circuitId, proofType, name, version, msg.sender);
        return circuitId;
    }

    /**
     * @dev Updates the status of an existing circuit.
     * @param circuitId ID of the circuit
     * @param newStatus New status to set
     */
    function updateCircuitStatus(
        bytes32 circuitId,
        uint8 newStatus
    ) external onlyRole(CIRCUIT_MANAGER_ROLE) whenNotPaused {
        require(_allCircuits.contains(circuitId), "Circuit not registered");
        require(newStatus <= CIRCUIT_STATUS_REVOKED, "Invalid status");

        Circuit storage circuit = circuits[circuitId];
        uint8 oldStatus = circuit.status;
        require(oldStatus != newStatus, "Status already set");

        circuit.status = newStatus;
        circuit.lastUpdateTime = block.timestamp;

        emit CircuitStatusChanged(circuitId, oldStatus, newStatus);
    }

    /**
     * @dev Updates the verification key of a circuit.
     * @param circuitId ID of the circuit
     * @param verificationKey New verification key
     */
    function updateCircuitVerificationKey(
        bytes32 circuitId,
        bytes memory verificationKey
    ) external onlyRole(CIRCUIT_MANAGER_ROLE) whenNotPaused {
        require(_allCircuits.contains(circuitId), "Circuit not registered");
        require(verificationKey.length > 0, "Verification key cannot be empty");

        Circuit storage circuit = circuits[circuitId];
        circuit.verificationKey = verificationKey;
        circuit.lastUpdateTime = block.timestamp;

        emit CircuitVerificationKeyUpdated(circuitId, msg.sender);
    }

    /**
     * @dev Updates the metadata of a circuit.
     * @param circuitId ID of the circuit
     * @param description New description
     * @param metadataURI New metadata URI
     */
    function updateCircuitMetadata(
        bytes32 circuitId,
        string memory description,
        string memory metadataURI
    ) external onlyRole(CIRCUIT_MANAGER_ROLE) whenNotPaused {
        require(_allCircuits.contains(circuitId), "Circuit not registered");

        Circuit storage circuit = circuits[circuitId];
        circuit.description = description;
        circuit.metadataURI = metadataURI;
        circuit.lastUpdateTime = block.timestamp;
    }

    /**
     * @dev Retrieves detailed information about a circuit.
     * @param circuitId ID of the circuit
     * @return proofType, name, description, version, status, creationTime, lastUpdateTime, createdBy, verificationKey, metadataURI
     */
    function getCircuitDetails(bytes32 circuitId)
        external
        view
        returns (
            bytes32 proofType,
            string memory name,
            string memory description,
            string memory version,
            uint8 status,
            uint256 creationTime,
            uint256 lastUpdateTime,
            address createdBy,
            bytes memory verificationKey,
            string memory metadataURI
        )
    {
        require(_allCircuits.contains(circuitId), "Circuit not registered");
        Circuit storage circuit = circuits[circuitId];
        return (
            circuit.proofType,
            circuit.name,
            circuit.description,
            circuit.version,
            circuit.status,
            circuit.creationTime,
            circuit.lastUpdateTime,
            circuit.createdBy,
            circuit.verificationKey,
            circuit.metadataURI
        );
    }

    /**
     * @dev Retrieves a circuit ID by its proof type and name.
     * @param proofType Type of proof
     * @param name Name of the circuit
     * @return circuitId ID of the circuit
     */
    function getCircuitByTypeAndName(bytes32 proofType, string memory name)
        external
        view
        returns (bytes32 circuitId)
    {
        circuitId = _circuitByTypeAndName[proofType][name];
        require(circuitId != bytes32(0), "Circuit not found");
        return circuitId;
    }

    /**
     * @dev Returns all registered circuit IDs.
     * @return Array of circuit IDs
     */
    function getAllCircuits() external view returns (bytes32[] memory) {
        return _allCircuits.values();
    }

    /**
     * @dev Retrieves the verification key of a circuit.
     * @param circuitId ID of the circuit
     * @return Verification key
     */
    function getCircuitVerificationKey(bytes32 circuitId) external view returns (bytes memory) {
        require(_allCircuits.contains(circuitId), "Circuit not registered");
        return circuits[circuitId].verificationKey;
    }

    // ==========================================================================
    // Proof Type Management
    // ==========================================================================

    /**
     * @dev Adds a new supported proof type.
     * @param proofType Type of proof as bytes32
     * @param name Human-readable name
     */
    function addProofType(bytes32 proofType, string memory name) external onlyRole(REGISTRY_ADMIN_ROLE) {
        require(proofType != bytes32(0), "Invalid proof type");
        require(bytes(name).length > 0, "Name cannot be empty");
        require(!_supportedProofTypes.contains(proofType), "Proof type already exists");

        _supportedProofTypes.add(proofType);
        emit ProofTypeAdded(proofType, name);
    }

    /**
     * @dev Returns all supported proof types.
     * @return Array of proof types
     */
    function getSupportedProofTypes() external view returns (bytes32[] memory) {
        return _supportedProofTypes.values();
    }

    // ==========================================================================
    // Verification Management
    // ==========================================================================

    /**
     * @dev Records the result of a proof verification.
     * @param proofId Unique ID of the proof
     * @param circuitId ID of the circuit used
     * @param verifierAddress Address of the verifier used
     * @param valid Whether the proof was valid
     * @param publicInputsHash Hash of the public inputs
     * @param verifiedFor Address the proof was verified for
     * @param gasUsed Gas used for verification
     */
    function recordVerification(
        bytes32 proofId,
        bytes32 circuitId,
        address verifierAddress,
        bool valid,
        bytes32 publicInputsHash,
        address verifiedFor,
        uint256 gasUsed
    ) external whenNotPaused nonReentrant {
        require(
            _allVerifiers.contains(msg.sender) || hasRole(VERIFIER_MANAGER_ROLE, msg.sender),
            "Not authorized to record verification"
        );
        require(_allCircuits.contains(circuitId), "Circuit not registered");
        require(_allVerifiers.contains(verifierAddress), "Verifier not registered");

        VerificationResult memory result = VerificationResult({
            proofId: proofId,
            circuitId: circuitId,
            verifier: verifierAddress,
            valid: valid,
            verificationTime: block.timestamp,
            publicInputsHash: publicInputsHash,
            verifiedFor: verifiedFor,
            gasUsed: gasUsed
        });

        verificationResults[proofId] = result;

        totalVerifications++;
        if (valid) {
            successfulVerifications++;
        } else {
            failedVerifications++;
        }

        totalGasUsed = totalGasUsed.add(gasUsed);
        averageGasUsed = totalVerifications > 0 ? totalGasUsed.div(totalVerifications) : 0;

        emit ProofVerified(proofId, circuitId, verifierAddress, valid);
    }

    /**
     * @dev Checks the validity and verification time of a proof.
     * @param proofId ID of the proof
     * @return valid Whether the proof was valid
     * @return verificationTime When the verification occurred
     */
    function checkProofValidity(bytes32 proofId) external view returns (bool valid, uint256 verificationTime) {
        VerificationResult storage result = verificationResults[proofId];
        require(result.verificationTime > 0, "Proof not verified");
        return (result.valid, result.verificationTime);
    }

    /**
     * @dev Retrieves detailed information about a proof verification.
     * @param proofId ID of the proof
     * @return circuitId, verifier, valid, verificationTime, publicInputsHash, verifiedFor, gasUsed
     */
    function getVerificationResult(bytes32 proofId)
        external
        view
        returns (
            bytes32 circuitId,
            address verifier,
            bool valid,
            uint256 verificationTime,
            bytes32 publicInputsHash,
            address verifiedFor,
            uint256 gasUsed
        )
    {
        VerificationResult storage result = verificationResults[proofId];
        require(result.verificationTime > 0, "Proof not verified");
        return (
            result.circuitId,
            result.verifier,
            result.valid,
            result.verificationTime,
            result.publicInputsHash,
            result.verifiedFor,
            result.gasUsed
        );
    }

    /**
     * @dev Returns verification statistics.
     * @return total Total verifications
     * @return successful Successful verifications
     * @return failed Failed verifications
     * @return avgGas Average gas used per verification
     */
    function getVerificationStats()
        external
        view
        returns (uint256 total, uint256 successful, uint256 failed, uint256 avgGas)
    {
        return (totalVerifications, successfulVerifications, failedVerifications, averageGasUsed);
    }

    // ==========================================================================
    // External Interfaces
    // ==========================================================================

    /**
     * @dev Checks if a verifier is trusted for a given proof type.
     * @param verifierAddress Address of the verifier
     * @param proofType Type of proof
     * @return Whether the verifier is trusted
     */
    function isTrustedVerifier(address verifierAddress, bytes32 proofType) external view returns (bool) {
        return _trustedVerifiers[proofType].contains(verifierAddress);
    }

    /**
     * @dev Finds a trusted verifier that supports a specific circuit.
     * @param circuitId ID of the circuit
     * @return Address of a trusted verifier, or address(0) if none found
     */
    function findTrustedVerifierForCircuit(bytes32 circuitId) external view returns (address) {
        require(_allCircuits.contains(circuitId), "Circuit not registered");
        bytes32 proofType = circuits[circuitId].proofType;

        uint256 verifierCount = _trustedVerifiers[proofType].length();
        for (uint256 i = 0; i < verifierCount; i++) {
            address verifierAddress = _trustedVerifiers[proofType].at(i);
            Verifier storage verifier = verifiers[verifierAddress];
            for (uint256 j = 0; j < verifier.supportedCircuits.length; j++) {
                if (verifier.supportedCircuits[j] == circuitId) {
                    return verifierAddress;
                }
            }
        }
        return address(0);
    }

    /**
     * @dev Finds all trusted verifiers that support a specific circuit.
     * @param circuitId ID of the circuit
     * @return Array of trusted verifier addresses
     */
    function findAllTrustedVerifiersForCircuit(bytes32 circuitId) external view returns (address[] memory) {
        require(_allCircuits.contains(circuitId), "Circuit not registered");
        bytes32 proofType = circuits[circuitId].proofType;

        uint256 verifierCount = _trustedVerifiers[proofType].length();
        address[] memory temp = new address[](verifierCount);
        uint256 count = 0;

        for (uint256 i = 0; i < verifierCount; i++) {
            address verifierAddress = _trustedVerifiers[proofType].at(i);
            Verifier storage verifier = verifiers[verifierAddress];
            for (uint256 j = 0; j < verifier.supportedCircuits.length; j++) {
                if (verifier.supportedCircuits[j] == circuitId) {
                    temp[count] = verifierAddress;
                    count++;
                    break;
                }
            }
        }

        address[] memory result = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = temp[i];
        }
        return result;
    }

    // ==========================================================================
    // Admin Functions
    // ==========================================================================

    /**
     * @dev Sets or removes a trusted forwarder for meta-transactions.
     * @param forwarder Address of the forwarder
     * @param trusted Whether to trust or untrust the forwarder
     */
    function setTrustedForwarder(address forwarder, bool trusted) external onlyRole(REGISTRY_ADMIN_ROLE) {
        if (trusted) {
            _grantRole(TRUSTED_FORWARDER_ROLE, forwarder);
        } else {
            _revokeRole(TRUSTED_FORWARDER_ROLE, forwarder);
        }
    }

    /**
     * @dev Pauses the contract, disabling non-view functions.
     */
    function pause() external onlyRole(REGISTRY_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @dev Unpauses the contract, re-enabling non-view functions.
     */
    function unpause() external onlyRole(REGISTRY_ADMIN_ROLE) {
        _unpause();
    }

    // ==========================================================================
    // Meta-Transactions Support
    // ==========================================================================

    /**
     * @dev Overrides _msgSender to support meta-transactions via trusted forwarders.
     * @return Address of the actual sender
     */
    function _msgSender() internal view virtual override returns (address) {
        if (hasRole(TRUSTED_FORWARDER_ROLE, msg.sender)) {
            bytes memory callData = msg.data;
            if (callData.length >= 20) {
                assembly {
                    let sender := mload(add(callData, sub(calldatasize(), 20)))
                    sender := shr(96, sender)
                    mstore(0, sender)
                    return(0, 32)
                }
            }
        }
        return super._msgSender();
    }
}
