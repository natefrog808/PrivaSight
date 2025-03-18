// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

interface IDataVaultNFT {
    function ownerOf(uint256 tokenId) external view returns (address);
    function getDataVaultInfo(uint256 tokenId) external view returns (
        string memory dataHash,
        string memory accessRules,
        string memory dataCategory,
        uint256 stakingAmount,
        uint256 lastUpdated
    );
}

interface IVerifierRegistry {
    function isTrustedVerifier(address verifierAddress, bytes32 proofType) external view returns (bool);
    function findTrustedVerifierForCircuit(bytes32 circuitId) external view returns (address);
    function checkProofValidity(bytes32 proofId) external view returns (bool valid, uint256 verificationTime);
}

interface IPrivacyLayer {
    function verifyComputationProof(
        bytes memory proof,
        bytes memory publicSignals,
        bytes32 computationId
    ) external view returns (bool);
}

/**
 * @title PrivaSight Result Publisher
 * @dev Secure publisher for computation results on the PrivaSight platform.
 * Manages verification, encryption, and controlled disclosure of computation
 * results with strong privacy and security guarantees.
 */
contract ResultPublisher is AccessControl, ReentrancyGuard, Pausable {
    using SafeMath for uint256;
    using ECDSA for bytes32;
    
    // ==========================================================================
    // Constants
    // ==========================================================================
    
    bytes32 public constant PUBLISHER_ROLE = keccak256("PUBLISHER_ROLE");
    bytes32 public constant COMPUTE_NODE_ROLE = keccak256("COMPUTE_NODE_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    
    // Result status
    uint8 public constant RESULT_STATUS_PENDING = 0;
    uint8 public constant RESULT_STATUS_VERIFIED = 1;
    uint8 public constant RESULT_STATUS_PUBLISHED = 2;
    uint8 public constant RESULT_STATUS_DISPUTED = 3;
    uint8 public constant RESULT_STATUS_INVALIDATED = 4;
    
    // Computation types
    uint8 public constant COMPUTATION_TYPE_STATISTICAL = 1;
    uint8 public constant COMPUTATION_TYPE_MACHINE_LEARNING = 2;
    uint8 public constant COMPUTATION_TYPE_DATA_QUERY = 3;
    uint8 public constant COMPUTATION_TYPE_CUSTOM = 4;
    
    // Privacy levels
    uint8 public constant PRIVACY_LEVEL_PUBLIC = 1;    // Results visible to anyone
    uint8 public constant PRIVACY_LEVEL_RESEARCHER = 2; // Results visible only to researcher
    uint8 public constant PRIVACY_LEVEL_OWNERS = 3;     // Results visible to data owners and researcher
    uint8 public constant PRIVACY_LEVEL_ENCRYPTED = 4;  // Results encrypted with researcher's key
    
    // Dispute resolution states
    uint8 public constant DISPUTE_STATE_OPENED = 1;
    uint8 public constant DISPUTE_STATE_UNDER_REVIEW = 2;
    uint8 public constant DISPUTE_STATE_RESOLVED = 3;
    uint8 public constant DISPUTE_STATE_REJECTED = 4;
    
    // Action types for audit log
    uint8 public constant ACTION_COMPUTATION_STARTED = 1;
    uint8 public constant ACTION_RESULT_SUBMITTED = 2;
    uint8 public constant ACTION_RESULT_VERIFIED = 3;
    uint8 public constant ACTION_RESULT_PUBLISHED = 4;
    uint8 public constant ACTION_RESULT_DISPUTED = 5;
    uint8 public constant ACTION_RESULT_INVALIDATED = 6;
    uint8 public constant ACTION_DISPUTE_RESOLVED = 7;
    
    // ==========================================================================
    // State Variables
    // ==========================================================================
    
    // External contract references
    IDataVaultNFT public dataVaultNFT;
    IVerifierRegistry public verifierRegistry;
    IPrivacyLayer public privacyLayer;
    
    // Mapping of computation ID to computation data
    struct Computation {
        bytes32 computationId;            // Unique ID of the computation
        address requester;                // Address that requested the computation
        uint8 computationType;            // Type of computation
        uint256[] dataVaultIds;           // Data vault IDs used in the computation
        string parameters;                // Computation parameters (JSON)
        uint256 requestTime;              // When the computation was requested
        address assignedNode;             // Compute node assigned to this computation
        uint256 assignedTime;             // When the compute node was assigned
        uint256 deadline;                 // Deadline for computation completion
        bytes32 circuitId;                // ID of the ZKP circuit for verification
        uint8 privacyLevel;               // Privacy level for the results
        bool emergency;                   // Whether this is an emergency computation
    }
    
    // Mapping of computation ID to result data
    struct ComputationResult {
        bytes32 computationId;            // ID of the associated computation
        address submitter;                // Address that submitted the result
        uint8 status;                     // Current status of the result
        uint256 submissionTime;           // When the result was submitted
        string resultMetadata;            // Metadata about the result (JSON)
        bytes encryptedResult;            // Encrypted result data
        string publicResult;              // Public summary or aggregated result (if applicable)
        bytes32 resultHash;               // Hash of the result for verification
        bytes zkProof;                    // Zero-knowledge proof of correct computation
        bytes32 proofId;                  // ID of the verified proof (if verified)
        uint256 verificationTime;         // When the result was verified
        address verifier;                 // Address that verified the result
        uint256 publishTime;              // When the result was published
        bytes[] signatures;               // Signatures from compute nodes
        address[] signers;                // Addresses of the signers
    }
    
    // Dispute information
    struct Dispute {
        bytes32 computationId;            // ID of the disputed computation
        address initiator;                // Address that initiated the dispute
        string reason;                    // Reason for the dispute
        uint8 state;                      // Current state of the dispute
        uint256 openTime;                 // When the dispute was opened
        uint256 resolutionTime;           // When the dispute was resolved
        address resolver;                 // Address that resolved the dispute
        string resolution;                // Resolution details
    }
    
    // Audit log entry
    struct AuditLogEntry {
        bytes32 computationId;            // ID of the computation
        uint8 actionType;                 // Type of action
        address actor;                    // Address that performed the action
        uint256 timestamp;                // When the action occurred
        string details;                   // Additional details
    }
    
    // Access control for results
    struct ResultAccess {
        bytes32 computationId;            // ID of the computation
        address grantee;                  // Address granted access
        uint256 grantTime;                // When access was granted
        uint256 expiryTime;               // When access expires
        bool revoked;                     // Whether access has been revoked
    }
    
    // Computation & result storage
    mapping(bytes32 => Computation) public computations;
    mapping(bytes32 => ComputationResult) public results;
    
    // All computation IDs
    bytes32[] public allComputationIds;
    
    // Computations by requester
    mapping(address => bytes32[]) private _requesterComputations;
    
    // Computations by data vault
    mapping(uint256 => bytes32[]) private _dataVaultComputations;
    
    // Computations by compute node
    mapping(address => bytes32[]) private _nodeComputations;
    
    // Disputes by computation ID
    mapping(bytes32 => Dispute[]) public disputes;
    
    // Audit log by computation ID
    mapping(bytes32 => AuditLogEntry[]) private _auditLog;
    
    // Result access grants
    mapping(bytes32 => mapping(address => ResultAccess)) private _resultAccess;
    mapping(address => bytes32[]) private _accessibleResults;
    
    // Node registration and stats
    struct ComputeNode {
        address nodeAddress;              // Address of the compute node
        string name;                      // Human-readable name
        string endpoint;                  // API endpoint for off-chain communication
        bytes publicKey;                  // Public key for encryption
        uint256 registerTime;             // When the node was registered
        uint256 lastActiveTime;           // Last activity time
        uint256 computationsCompleted;    // Number of computations completed
        uint256 computationsFailed;       // Number of computations failed
        uint256 disputesResolved;         // Number of disputes resolved
        bool active;                      // Whether the node is active
    }
    
    // Compute node registry
    mapping(address => ComputeNode) public computeNodes;
    address[] public allComputeNodes;
    
    // Platform statistics
    uint256 public totalComputations;
    uint256 public completedComputations;
    uint256 public failedComputations;
    uint256 public disputedComputations;
    uint256 public totalDisputes;
    uint256 public resolvedDisputes;
    
    // Events
    event ComputationRequested(
        bytes32 indexed computationId,
        address indexed requester,
        uint8 computationType,
        uint256[] dataVaultIds,
        uint8 privacyLevel
    );
    
    event ComputeNodeAssigned(
        bytes32 indexed computationId,
        address indexed nodeAddress,
        uint256 deadline
    );
    
    event ResultSubmitted(
        bytes32 indexed computationId,
        address indexed submitter,
        bytes32 resultHash,
        uint256 submissionTime
    );
    
    event ResultVerified(
        bytes32 indexed computationId,
        address indexed verifier,
        bytes32 proofId,
        uint256 verificationTime
    );
    
    event ResultPublished(
        bytes32 indexed computationId,
        address indexed publisher,
        uint256 publishTime,
        uint8 privacyLevel
    );
    
    event ResultDisputed(
        bytes32 indexed computationId,
        address indexed initiator,
        string reason,
        uint256 openTime
    );
    
    event DisputeResolved(
        bytes32 indexed computationId,
        address indexed resolver,
        uint8 resolution,
        uint256 resolutionTime
    );
    
    event ResultAccessGranted(
        bytes32 indexed computationId,
        address indexed grantee,
        uint256 expiryTime
    );
    
    event ResultAccessRevoked(
        bytes32 indexed computationId,
        address indexed grantee,
        uint256 revokeTime
    );
    
    event ComputeNodeRegistered(
        address indexed nodeAddress,
        string name,
        string endpoint,
        uint256 registerTime
    );
    
    event ComputeNodeStatusChanged(
        address indexed nodeAddress,
        bool active,
        uint256 timestamp
    );
    
    // ==========================================================================
    // Constructor
    // ==========================================================================
    
    /**
     * @dev Initializes the Result Publisher contract.
     * @param _dataVaultNFT Address of the DataVault NFT contract
     * @param _verifierRegistry Address of the Verifier Registry contract
     * @param _privacyLayer Address of the Privacy Layer contract
     */
    constructor(
        address _dataVaultNFT,
        address _verifierRegistry,
        address _privacyLayer
    ) {
        require(_dataVaultNFT != address(0), "Invalid DataVault NFT address");
        require(_verifierRegistry != address(0), "Invalid Verifier Registry address");
        
        dataVaultNFT = IDataVaultNFT(_dataVaultNFT);
        verifierRegistry = IVerifierRegistry(_verifierRegistry);
        
        // Privacy layer can be set later
        if (_privacyLayer != address(0)) {
            privacyLayer = IPrivacyLayer(_privacyLayer);
        }
        
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PUBLISHER_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);
    }
    
    // ==========================================================================
    // Computation Management
    // ==========================================================================
    
    /**
     * @dev Request a new computation.
     * @param computationType Type of computation
     * @param dataVaultIds Array of DataVault IDs to include
     * @param parameters Computation parameters (JSON)
     * @param privacyLevel Privacy level for the results
     * @param circuitId ID of the ZKP circuit for verification
     * @param emergency Whether this is an emergency computation
     * @return computationId Unique ID of the created computation
     */
    function requestComputation(
        uint8 computationType,
        uint256[] memory dataVaultIds,
        string memory parameters,
        uint8 privacyLevel,
        bytes32 circuitId,
        bool emergency
    ) 
        external
        whenNotPaused
        nonReentrant
        returns (bytes32 computationId)
    {
        require(dataVaultIds.length > 0, "No DataVaults specified");
        require(computationType >= COMPUTATION_TYPE_STATISTICAL && computationType <= COMPUTATION_TYPE_CUSTOM, "Invalid computation type");
        require(privacyLevel >= PRIVACY_LEVEL_PUBLIC && privacyLevel <= PRIVACY_LEVEL_ENCRYPTED, "Invalid privacy level");
        
        // Check authorization for emergency computations
        if (emergency) {
            require(hasRole(EMERGENCY_ROLE, msg.sender), "Not authorized for emergency computation");
        }
        
        // Check access to all data vaults
        for (uint256 i = 0; i < dataVaultIds.length; i++) {
            uint256 dataVaultId = dataVaultIds[i];
            address owner = dataVaultNFT.ownerOf(dataVaultId);
            
            // Require caller to be the owner or have explicit permission
            // (In a real implementation, this would check against AccessControl contract)
            require(owner == msg.sender, "Not authorized for all DataVaults");
        }
        
        // Generate unique computation ID
        computationId = keccak256(abi.encodePacked(
            msg.sender,
            block.timestamp,
            dataVaultIds,
            parameters
        ));
        
        // Ensure computation ID doesn't already exist
        require(computations[computationId].requestTime == 0, "Computation already exists");
        
        // Create computation
        Computation storage computation = computations[computationId];
        computation.computationId = computationId;
        computation.requester = msg.sender;
        computation.computationType = computationType;
        computation.dataVaultIds = dataVaultIds;
        computation.parameters = parameters;
        computation.requestTime = block.timestamp;
        computation.circuitId = circuitId;
        computation.privacyLevel = privacyLevel;
        computation.emergency = emergency;
        
        // Add to indices
        allComputationIds.push(computationId);
        _requesterComputations[msg.sender].push(computationId);
        
        for (uint256 i = 0; i < dataVaultIds.length; i++) {
            _dataVaultComputations[dataVaultIds[i]].push(computationId);
        }
        
        // Log the action
        _addAuditLogEntry(
            computationId,
            ACTION_COMPUTATION_STARTED,
            msg.sender,
            "Computation request submitted"
        );
        
        // Update statistics
        totalComputations++;
        
        emit ComputationRequested(
            computationId,
            msg.sender,
            computationType,
            dataVaultIds,
            privacyLevel
        );
        
        return computationId;
    }
    
    /**
     * @dev Assign a compute node to a computation.
     * @param computationId ID of the computation
     * @param nodeAddress Address of the compute node
     * @param deadline Deadline for computation completion
     */
    function assignComputeNode(
        bytes32 computationId,
        address nodeAddress,
        uint256 deadline
    ) 
        external
        onlyRole(PUBLISHER_ROLE)
        whenNotPaused
    {
        require(computations[computationId].requestTime > 0, "Computation does not exist");
        require(computations[computationId].assignedNode == address(0), "Compute node already assigned");
        require(computeNodes[nodeAddress].active, "Compute node not active");
        require(deadline > block.timestamp, "Deadline must be in the future");
        
        // Assign compute node
        computations[computationId].assignedNode = nodeAddress;
        computations[computationId].assignedTime = block.timestamp;
        computations[computationId].deadline = deadline;
        
        // Add to node's computations
        _nodeComputations[nodeAddress].push(computationId);
        
        // Update node's last activity time
        computeNodes[nodeAddress].lastActiveTime = block.timestamp;
        
        emit ComputeNodeAssigned(
            computationId,
            nodeAddress,
            deadline
        );
    }
    
    /**
     * @dev Get computation details.
     * @param computationId ID of the computation
     * @return requester Address that requested the computation
     * @return computationType Type of computation
     * @return dataVaultIds Data vault IDs used in the computation
     * @return parameters Computation parameters
     * @return requestTime When the computation was requested
     * @return assignedNode Compute node assigned to this computation
     * @return assignedTime When the compute node was assigned
     * @return deadline Deadline for computation completion
     * @return circuitId ID of the ZKP circuit for verification
     * @return privacyLevel Privacy level for the results
     * @return emergency Whether this is an emergency computation
     */
    function getComputationDetails(bytes32 computationId) 
        external 
        view 
        returns (
            address requester,
            uint8 computationType,
            uint256[] memory dataVaultIds,
            string memory parameters,
            uint256 requestTime,
            address assignedNode,
            uint256 assignedTime,
            uint256 deadline,
            bytes32 circuitId,
            uint8 privacyLevel,
            bool emergency
        ) 
    {
        Computation storage computation = computations[computationId];
        require(computation.requestTime > 0, "Computation does not exist");
        
        return (
            computation.requester,
            computation.computationType,
            computation.dataVaultIds,
            computation.parameters,
            computation.requestTime,
            computation.assignedNode,
            computation.assignedTime,
            computation.deadline,
            computation.circuitId,
            computation.privacyLevel,
            computation.emergency
        );
    }
    
    /**
     * @dev Get computations requested by an address.
     * @param requester Address of the requester
     * @return Array of computation IDs
     */
    function getRequesterComputations(address requester) 
        external 
        view 
        returns (bytes32[] memory) 
    {
        return _requesterComputations[requester];
    }
    
    /**
     * @dev Get computations involving a specific DataVault.
     * @param dataVaultId ID of the DataVault
     * @return Array of computation IDs
     */
    function getDataVaultComputations(uint256 dataVaultId) 
        external 
        view 
        returns (bytes32[] memory) 
    {
        return _dataVaultComputations[dataVaultId];
    }
    
    /**
     * @dev Get computations assigned to a compute node.
     * @param nodeAddress Address of the compute node
     * @return Array of computation IDs
     */
    function getNodeComputations(address nodeAddress) 
        external 
        view 
        returns (bytes32[] memory) 
    {
        return _nodeComputations[nodeAddress];
    }
    
    // ==========================================================================
    // Result Submission and Verification
    // ==========================================================================
    
    /**
     * @dev Submit a computation result.
     * @param computationId ID of the computation
     * @param resultMetadata Metadata about the result (JSON)
     * @param encryptedResult Encrypted result data
     * @param publicResult Public summary or aggregated result
     * @param resultHash Hash of the result for verification
     * @param zkProof Zero-knowledge proof of correct computation
     * @param signatures Signatures from compute nodes
     * @param signers Addresses of the signers
     */
    function submitResult(
        bytes32 computationId,
        string memory resultMetadata,
        bytes memory encryptedResult,
        string memory publicResult,
        bytes32 resultHash,
        bytes memory zkProof,
        bytes[] memory signatures,
        address[] memory signers
    ) 
        external
        whenNotPaused
        nonReentrant
    {
        Computation storage computation = computations[computationId];
        require(computation.requestTime > 0, "Computation does not exist");
        
        // Check authorization
        require(
            computation.assignedNode == msg.sender || 
            hasRole(COMPUTE_NODE_ROLE, msg.sender) ||
            hasRole(PUBLISHER_ROLE, msg.sender),
            "Not authorized to submit result"
        );
        
        // Ensure result doesn't already exist
        require(results[computationId].submissionTime == 0, "Result already submitted");
        
        // Validate signatures if provided
        if (signatures.length > 0) {
            require(signatures.length == signers.length, "Signatures and signers mismatch");
            
            for (uint256 i = 0; i < signatures.length; i++) {
                // Verify signature
                bytes32 messageHash = keccak256(abi.encodePacked(computationId, resultHash));
                bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
                address recovered = ethSignedMessageHash.recover(signatures[i]);
                
                require(recovered == signers[i], "Invalid signature");
                require(hasRole(COMPUTE_NODE_ROLE, recovered), "Signer is not a compute node");
            }
        }
        
        // Create result
        ComputationResult storage result = results[computationId];
        result.computationId = computationId;
        result.submitter = msg.sender;
        result.status = RESULT_STATUS_PENDING;
        result.submissionTime = block.timestamp;
        result.resultMetadata = resultMetadata;
        result.encryptedResult = encryptedResult;
        result.publicResult = publicResult;
        result.resultHash = resultHash;
        result.zkProof = zkProof;
        result.signatures = signatures;
        result.signers = signers;
        
        // Log the action
        _addAuditLogEntry(
            computationId,
            ACTION_RESULT_SUBMITTED,
            msg.sender,
            "Result submitted"
        );
        
        // Update compute node stats if applicable
        if (hasRole(COMPUTE_NODE_ROLE, msg.sender)) {
            computeNodes[msg.sender].lastActiveTime = block.timestamp;
            computeNodes[msg.sender].computationsCompleted++;
        }
        
        emit ResultSubmitted(
            computationId,
            msg.sender,
            resultHash,
            block.timestamp
        );
    }
    
    /**
     * @dev Verify a computation result using ZKP.
     * @param computationId ID of the computation
     * @param proofId ID of the proof in the Verifier Registry
     */
    function verifyResult(
        bytes32 computationId,
        bytes32 proofId
    ) 
        external
        onlyRole(VERIFIER_ROLE)
        whenNotPaused
    {
        ComputationResult storage result = results[computationId];
        require(result.submissionTime > 0, "Result not submitted");
        require(result.status == RESULT_STATUS_PENDING, "Result not in pending status");
        
        // Check proof validity in Verifier Registry
        (bool valid, uint256 verificationTime) = verifierRegistry.checkProofValidity(proofId);
        require(valid, "Proof is not valid");
        
        // Update result status
        result.status = RESULT_STATUS_VERIFIED;
        result.proofId = proofId;
        result.verificationTime = block.timestamp;
        result.verifier = msg.sender;
        
        // Log the action
        _addAuditLogEntry(
            computationId,
            ACTION_RESULT_VERIFIED,
            msg.sender,
            "Result verified with zkp"
        );
        
        emit ResultVerified(
            computationId,
            msg.sender,
            proofId,
            block.timestamp
        );
    }
    
    /**
     * @dev Verify a result using the Privacy Layer's verification.
     * @param computationId ID of the computation
     * @param proof ZKP proof
     * @param publicSignals Public signals for the proof
     */
    function verifyResultWithPrivacyLayer(
        bytes32 computationId,
        bytes memory proof,
        bytes memory publicSignals
    ) 
        external
        onlyRole(VERIFIER_ROLE)
        whenNotPaused
    {
        require(address(privacyLayer) != address(0), "Privacy layer not set");
        
        ComputationResult storage result = results[computationId];
        require(result.submissionTime > 0, "Result not submitted");
        require(result.status == RESULT_STATUS_PENDING, "Result not in pending status");
        
        // Verify using privacy layer
        bool valid = privacyLayer.verifyComputationProof(proof, publicSignals, computationId);
        require(valid, "Proof verification failed");
        
        // Update result status
        result.status = RESULT_STATUS_VERIFIED;
        result.verificationTime = block.timestamp;
        result.verifier = msg.sender;
        
        // Generate a proofId for reference
        bytes32 proofId = keccak256(abi.encodePacked(computationId, proof, block.timestamp));
        result.proofId = proofId;
        
        // Log the action
        _addAuditLogEntry(
            computationId,
            ACTION_RESULT_VERIFIED,
            msg.sender,
            "Result verified with privacy layer"
        );
        
        emit ResultVerified(
            computationId,
            msg.sender,
            proofId,
            block.timestamp
        );
    }
    
    /**
     * @dev Publish a verified result, making it accessible according to privacy level.
     * @param computationId ID of the computation
     */
    function publishResult(
        bytes32 computationId
    ) 
        external
        onlyRole(PUBLISHER_ROLE)
        whenNotPaused
    {
        ComputationResult storage result = results[computationId];
        require(result.submissionTime > 0, "Result not submitted");
        require(result.status == RESULT_STATUS_VERIFIED, "Result not verified");
        
        // Get computation for privacy level
        Computation storage computation = computations[computationId];
        
        // Update result status
        result.status = RESULT_STATUS_PUBLISHED;
        result.publishTime = block.timestamp;
        
        // Grant access to appropriate parties based on privacy level
        if (computation.privacyLevel == PRIVACY_LEVEL_PUBLIC) {
            // No additional access control needed for public results
        } else if (computation.privacyLevel == PRIVACY_LEVEL_RESEARCHER) {
            // Grant access to the researcher only
            _grantResultAccess(computationId, computation.requester, 0); // No expiry for requester
        } else if (computation.privacyLevel == PRIVACY_LEVEL_OWNERS) {
            // Grant access to data owners and researcher
            _grantResultAccess(computationId, computation.requester, 0); // No expiry for requester
            
            // Grant access to each data owner
            for (uint256 i = 0; i < computation.dataVaultIds.length; i++) {
                address owner = dataVaultNFT.ownerOf(computation.dataVaultIds[i]);
                _grantResultAccess(computationId, owner, 0); // No expiry for owners
            }
        } else if (computation.privacyLevel == PRIVACY_LEVEL_ENCRYPTED) {
            // Grant access to the researcher only, result is already encrypted with their key
            _grantResultAccess(computationId, computation.requester, 0); // No expiry for requester
        }
        
        // Log the action
        _addAuditLogEntry(
            computationId,
            ACTION_RESULT_PUBLISHED,
            msg.sender,
            "Result published"
        );
        
        // Update statistics
        completedComputations++;
        
        emit ResultPublished(
            computationId,
            msg.sender,
            block.timestamp,
            computation.privacyLevel
        );
    }
    
    /**
     * @dev Invalidate a result (e.g., due to a successful dispute).
     * @param computationId ID of the computation
     * @param reason Reason for invalidation
     */
    function invalidateResult(
        bytes32 computationId,
        string memory reason
    ) 
        external
        onlyRole(PUBLISHER_ROLE)
        whenNotPaused
    {
        ComputationResult storage result = results[computationId];
        require(result.submissionTime > 0, "Result not submitted");
        require(result.status != RESULT_STATUS_INVALIDATED, "Result already invalidated");
        
        // Update result status
        result.status = RESULT_STATUS_INVALIDATED;
        
        // Log the action
        _addAuditLogEntry(
            computationId,
            ACTION_RESULT_INVALIDATED,
            msg.sender,
            reason
        );
        
        // Update statistics
        failedComputations++;
        
        // Update compute node stats if applicable
        if (hasRole(COMPUTE_NODE_ROLE, result.submitter)) {
            computeNodes[result.submitter].computationsFailed++;
        }
    }
    
    /**
     * @dev Get result details.
     * @param computationId ID of the computation
     * @return submitter Address that submitted the result
     * @return status Current status of the result
     * @return submissionTime When the result was submitted
     * @return resultMetadata Metadata about the result
     * @return resultHash Hash of the result
     * @return verificationTime When the result was verified
     * @return verifier Address that verified the result
     * @return publishTime When the result was published
     * @return signatureCount Number of signatures on the result
     */
    function getResultDetails(bytes32 computationId) 
        external 
        view 
        returns (
            address submitter,
            uint8 status,
            uint256 submissionTime,
            string memory resultMetadata,
            bytes32 resultHash,
            uint256 verificationTime,
            address verifier,
            uint256 publishTime,
            uint256 signatureCount
        ) 
    {
        ComputationResult storage result = results[computationId];
        require(result.submissionTime > 0, "Result not submitted");
        
        return (
            result.submitter,
            result.status,
            result.submissionTime,
            result.resultMetadata,
            result.resultHash,
            result.verificationTime,
            result.verifier,
            result.publishTime,
            result.signatures.length
        );
    }
    
    /**
     * @dev Get the result content (encrypted or public, depending on privacy level).
     * @param computationId ID of the computation
     * @return encryptedResult Encrypted result data (if accessible)
     * @return publicResult Public summary or aggregated result
     * @return accessible Whether the caller has access to the encrypted result
     */
    function getResultContent(bytes32 computationId) 
        external 
        view 
        returns (
            bytes memory encryptedResult,
            string memory publicResult,
            bool accessible
        ) 
    {
        ComputationResult storage result = results[computationId];
        require(result.submissionTime > 0, "Result not submitted");
        
        Computation storage computation = computations[computationId];
        
        // Determine if caller has access
        bool hasAccess = false;
        
        // Public results are accessible to everyone
        if (computation.privacyLevel == PRIVACY_LEVEL_PUBLIC) {
            hasAccess = true;
        } else {
            // Check if caller is the requester
            if (computation.requester == msg.sender) {
                hasAccess = true;
            }
            // Check if caller is a data owner (for PRIVACY_LEVEL_OWNERS)
            else if (computation.privacyLevel == PRIVACY_LEVEL_OWNERS) {
                for (uint256 i = 0; i < computation.dataVaultIds.length; i++) {
                    if (dataVaultNFT.ownerOf(computation.dataVaultIds[i]) == msg.sender) {
                        hasAccess = true;
                        break;
                    }
                }
            }
            // Check explicit access grants
            else if (_resultAccess[computationId][msg.sender].grantTime > 0 && 
                    !_resultAccess[computationId][msg.sender].revoked &&
                    (_resultAccess[computationId][msg.sender].expiryTime == 0 || 
                     _resultAccess[computationId][msg.sender].expiryTime > block.timestamp)) {
                hasAccess = true;
            }
            // Admins always have access
            else if (hasRole(PUBLISHER_ROLE, msg.sender) || hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
                hasAccess = true;
            }
        }
        
        // Return appropriate content based on access
        if (hasAccess) {
            return (result.encryptedResult, result.publicResult, true);
        } else {
            // If no access, return only public result (if any)
            return (new bytes(0), result.publicResult, false);
        }
    }
    
    // ==========================================================================
    // Dispute Management
    // ==========================================================================
    
    /**
     * @dev Open a dispute about a computation result.
     * @param computationId ID of the computation
     * @param reason Reason for the dispute
     * @return disputeId Index of the created dispute
     */
    function openDispute(
        bytes32 computationId,
        string memory reason
    ) 
        external
        whenNotPaused
        nonReentrant
        returns (uint256 disputeId)
    {
        ComputationResult storage result = results[computationId];
        require(result.submissionTime > 0, "Result not submitted");
        require(result.status != RESULT_STATUS_INVALIDATED, "Result already invalidated");
        
        // Check if caller is authorized to dispute
        Computation storage computation = computations[computationId];
        bool isAuthorized = false;
        
        // Requester can always dispute
        if (computation.requester == msg.sender) {
            isAuthorized = true;
        }
        // Data owners can dispute if they own any of the data vaults
        else {
            for (uint256 i = 0; i < computation.dataVaultIds.length; i++) {
                if (dataVaultNFT.ownerOf(computation.dataVaultIds[i]) == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        
        require(isAuthorized, "Not authorized to open dispute");
        
        // Create dispute
        Dispute memory dispute = Dispute({
            computationId: computationId,
            initiator: msg.sender,
            reason: reason,
            state: DISPUTE_STATE_OPENED,
            openTime: block.timestamp,
            resolutionTime: 0,
            resolver: address(0),
            resolution: ""
        });
        
        disputes[computationId].push(dispute);
        disputeId = disputes[computationId].length - 1;
        
        // Update result status
        result.status = RESULT_STATUS_DISPUTED;
        
        // Log the action
        _addAuditLogEntry(
            computationId,
            ACTION_RESULT_DISPUTED,
            msg.sender,
            reason
        );
        
        // Update statistics
        disputedComputations++;
        totalDisputes++;
        
        emit ResultDisputed(
            computationId,
            msg.sender,
            reason,
            block.timestamp
        );
        
        return disputeId;
    }
    
    /**
     * @dev Resolve a dispute.
     * @param computationId ID of the computation
     * @param disputeId Index of the dispute
     * @param resolution Resolution details
     * @param upheld Whether the dispute is upheld (true) or rejected (false)
     */
    function resolveDispute(
        bytes32 computationId,
        uint256 disputeId,
        string memory resolution,
        bool upheld
    ) 
        external
        onlyRole(PUBLISHER_ROLE)
        whenNotPaused
    {
        require(disputeId < disputes[computationId].length, "Dispute does not exist");
        
        Dispute storage dispute = disputes[computationId][disputeId];
        require(dispute.state == DISPUTE_STATE_OPENED || dispute.state == DISPUTE_STATE_UNDER_REVIEW, "Dispute not open or under review");
        
        // Update dispute state
        dispute.state = upheld ? DISPUTE_STATE_RESOLVED : DISPUTE_STATE_REJECTED;
        dispute.resolutionTime = block.timestamp;
        dispute.resolver = msg.sender;
        dispute.resolution = resolution;
        
        // If dispute is upheld, invalidate the result
        if (upheld) {
            ComputationResult storage result = results[computationId];
            result.status = RESULT_STATUS_INVALIDATED;
            
            // Update statistics
            failedComputations++;
            
            // Update compute node stats if applicable
            if (hasRole(COMPUTE_NODE_ROLE, result.submitter)) {
                computeNodes[result.submitter].computationsFailed++;
            }
        } else {
            // If dispute is rejected, restore the previous status
            ComputationResult storage result = results[computationId];
            if (result.verificationTime > 0) {
                result.status = RESULT_STATUS_VERIFIED;
            } else {
                result.status = RESULT_STATUS_PENDING;
            }
        }
        
        // Log the action
        _addAuditLogEntry(
            computationId,
            ACTION_DISPUTE_RESOLVED,
            msg.sender,
            resolution
        );
        
        // Update statistics
        resolvedDisputes++;
        
        // Update compute node stats if resolver is a compute node
        if (hasRole(COMPUTE_NODE_ROLE, msg.sender)) {
            computeNodes[msg.sender].disputesResolved++;
        }
        
        emit DisputeResolved(
            computationId,
            msg.sender,
            upheld ? uint8(DISPUTE_STATE_RESOLVED) : uint8(DISPUTE_STATE_REJECTED),
            block.timestamp
        );
    }
    
    /**
     * @dev Get disputes for a computation.
     * @param computationId ID of the computation
     * @return Array of disputes
     */
    function getDisputes(bytes32 computationId) 
        external 
        view 
        returns (Dispute[] memory) 
    {
        return disputes[computationId];
    }
    
    // ==========================================================================
    // Result Access Management
    // ==========================================================================
    
    /**
     * @dev Grant access to a result.
     * @param computationId ID of the computation
     * @param grantee Address to grant access to
     * @param expiryTime When access expires (0 for no expiry)
     */
    function grantResultAccess(
        bytes32 computationId,
        address grantee,
        uint256 expiryTime
    ) 
        external
        whenNotPaused
    {
        ComputationResult storage result = results[computationId];
        require(result.submissionTime > 0, "Result not submitted");
        
        // Check if caller is authorized to grant access
        Computation storage computation = computations[computationId];
        bool isAuthorized = false;
        
        // Requester can grant access
        if (computation.requester == msg.sender) {
            isAuthorized = true;
        }
        // Admin or publisher can grant access
        else if (hasRole(PUBLISHER_ROLE, msg.sender) || hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            isAuthorized = true;
        }
        // Data owners can grant access if they own any of the data vaults
        else {
            for (uint256 i = 0; i < computation.dataVaultIds.length; i++) {
                if (dataVaultNFT.ownerOf(computation.dataVaultIds[i]) == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        
        require(isAuthorized, "Not authorized to grant access");
        
        // Grant access
        _grantResultAccess(computationId, grantee, expiryTime);
    }
    
    /**
     * @dev Internal function to grant access to a result.
     * @param computationId ID of the computation
     * @param grantee Address to grant access to
     * @param expiryTime When access expires (0 for no expiry)
     */
    function _grantResultAccess(
        bytes32 computationId,
        address grantee,
        uint256 expiryTime
    ) 
        private 
    {
        // Create access grant
        ResultAccess storage access = _resultAccess[computationId][grantee];
        access.computationId = computationId;
        access.grantee = grantee;
        access.grantTime = block.timestamp;
        access.expiryTime = expiryTime;
        access.revoked = false;
        
        // Add to accessible results for grantee
        bool alreadyAccessible = false;
        for (uint256 i = 0; i < _accessibleResults[grantee].length; i++) {
            if (_accessibleResults[grantee][i] == computationId) {
                alreadyAccessible = true;
                break;
            }
        }
        
        if (!alreadyAccessible) {
            _accessibleResults[grantee].push(computationId);
        }
        
        emit ResultAccessGranted(
            computationId,
            grantee,
            expiryTime
        );
    }
    
    /**
     * @dev Revoke access to a result.
     * @param computationId ID of the computation
     * @param grantee Address to revoke access from
     */
    function revokeResultAccess(
        bytes32 computationId,
        address grantee
    ) 
        external
        whenNotPaused
    {
        // Check if caller is authorized to revoke access
        Computation storage computation = computations[computationId];
        bool isAuthorized = false;
        
        // Requester can revoke access
        if (computation.requester == msg.sender) {
            isAuthorized = true;
        }
        // Admin or publisher can revoke access
        else if (hasRole(PUBLISHER_ROLE, msg.sender) || hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            isAuthorized = true;
        }
        // Data owners can revoke access if they own any of the data vaults
        else {
            for (uint256 i = 0; i < computation.dataVaultIds.length; i++) {
                if (dataVaultNFT.ownerOf(computation.dataVaultIds[i]) == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        
        require(isAuthorized, "Not authorized to revoke access");
        
        // Ensure access was granted
        ResultAccess storage access = _resultAccess[computationId][grantee];
        require(access.grantTime > 0, "Access not granted");
        require(!access.revoked, "Access already revoked");
        
        // Revoke access
        access.revoked = true;
        
        emit ResultAccessRevoked(
            computationId,
            grantee,
            block.timestamp
        );
    }
    
    /**
     * @dev Check if an address has access to a result.
     * @param computationId ID of the computation
     * @param grantee Address to check
     * @return Whether the address has access
     */
    function hasResultAccess(
        bytes32 computationId,
        address grantee
    ) 
        external 
        view 
        returns (bool) 
    {
        ComputationResult storage result = results[computationId];
        if (result.submissionTime == 0) {
            return false; // Result doesn't exist
        }
        
        Computation storage computation = computations[computationId];
        
        // Public results are accessible to everyone
        if (computation.privacyLevel == PRIVACY_LEVEL_PUBLIC) {
            return true;
        }
        
        // Check if caller is the requester
        if (computation.requester == grantee) {
            return true;
        }
        
        // Check if caller is a data owner (for PRIVACY_LEVEL_OWNERS)
        if (computation.privacyLevel == PRIVACY_LEVEL_OWNERS) {
            for (uint256 i = 0; i < computation.dataVaultIds.length; i++) {
                if (dataVaultNFT.ownerOf(computation.dataVaultIds[i]) == grantee) {
                    return true;
                }
            }
        }
        
        // Check explicit access grants
        ResultAccess storage access = _resultAccess[computationId][grantee];
        if (access.grantTime > 0 && !access.revoked) {
            if (access.expiryTime == 0 || access.expiryTime > block.timestamp) {
                return true;
            }
        }
        
        // Admins always have access
        if (hasRole(PUBLISHER_ROLE, grantee) || hasRole(DEFAULT_ADMIN_ROLE, grantee)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * @dev Get accessible results for an address.
     * @param grantee Address to check
     * @return Array of computation IDs
     */
    function getAccessibleResults(address grantee) 
        external 
        view 
        returns (bytes32[] memory) 
    {
        return _accessibleResults[grantee];
    }
    
    // ==========================================================================
    // Compute Node Management
    // ==========================================================================
    
    /**
     * @dev Register a compute node.
     * @param nodeAddress Address of the compute node
     * @param name Human-readable name
     * @param endpoint API endpoint for off-chain communication
     * @param publicKey Public key for encryption
     */
    function registerComputeNode(
        address nodeAddress,
        string memory name,
        string memory endpoint,
        bytes memory publicKey
    ) 
        external
        onlyRole(PUBLISHER_ROLE)
        whenNotPaused
    {
        require(nodeAddress != address(0), "Invalid node address");
        require(bytes(name).length > 0, "Name cannot be empty");
        require(bytes(endpoint).length > 0, "Endpoint cannot be empty");
        require(publicKey.length > 0, "Public key cannot be empty");
        
        // Check if node already exists
        require(computeNodes[nodeAddress].registerTime == 0, "Node already registered");
        
        // Create compute node
        ComputeNode storage node = computeNodes[nodeAddress];
        node.nodeAddress = nodeAddress;
        node.name = name;
        node.endpoint = endpoint;
        node.publicKey = publicKey;
        node.registerTime = block.timestamp;
        node.lastActiveTime = block.timestamp;
        node.computationsCompleted = 0;
        node.computationsFailed = 0;
        node.disputesResolved = 0;
        node.active = true;
        
        // Add to list of compute nodes
        allComputeNodes.push(nodeAddress);
        
        // Grant compute node role
        _grantRole(COMPUTE_NODE_ROLE, nodeAddress);
        
        emit ComputeNodeRegistered(
            nodeAddress,
            name,
            endpoint,
            block.timestamp
        );
    }
    
    /**
     * @dev Update compute node status.
     * @param nodeAddress Address of the compute node
     * @param active Whether the node is active
     */
    function updateComputeNodeStatus(
        address nodeAddress,
        bool active
    ) 
        external
        onlyRole(PUBLISHER_ROLE)
        whenNotPaused
    {
        require(computeNodes[nodeAddress].registerTime > 0, "Node not registered");
        
        // Update status
        computeNodes[nodeAddress].active = active;
        computeNodes[nodeAddress].lastActiveTime = block.timestamp;
        
        emit ComputeNodeStatusChanged(
            nodeAddress,
            active,
            block.timestamp
        );
    }
    
    /**
     * @dev Update compute node details.
     * @param nodeAddress Address of the compute node
     * @param name Human-readable name
     * @param endpoint API endpoint for off-chain communication
     * @param publicKey Public key for encryption
     */
    function updateComputeNodeDetails(
        address nodeAddress,
        string memory name,
        string memory endpoint,
        bytes memory publicKey
    ) 
        external
        onlyRole(PUBLISHER_ROLE)
        whenNotPaused
    {
        require(computeNodes[nodeAddress].registerTime > 0, "Node not registered");
        
        // Update details
        computeNodes[nodeAddress].name = name;
        computeNodes[nodeAddress].endpoint = endpoint;
        computeNodes[nodeAddress].publicKey = publicKey;
        computeNodes[nodeAddress].lastActiveTime = block.timestamp;
    }
    
    /**
     * @dev Get compute node details.
     * @param nodeAddress Address of the compute node
     * @return name Human-readable name
     * @return endpoint API endpoint for off-chain communication
     * @return publicKey Public key for encryption
     * @return registerTime When the node was registered
     * @return lastActiveTime Last activity time
     * @return computationsCompleted Number of computations completed
     * @return computationsFailed Number of computations failed
     * @return disputesResolved Number of disputes resolved
     * @return active Whether the node is active
     */
    function getComputeNodeDetails(address nodeAddress) 
        external 
        view 
        returns (
            string memory name,
            string memory endpoint,
            bytes memory publicKey,
            uint256 registerTime,
            uint256 lastActiveTime,
            uint256 computationsCompleted,
            uint256 computationsFailed,
            uint256 disputesResolved,
            bool active
        ) 
    {
        ComputeNode storage node = computeNodes[nodeAddress];
        require(node.registerTime > 0, "Node not registered");
        
        return (
            node.name,
            node.endpoint,
            node.publicKey,
            node.registerTime,
            node.lastActiveTime,
            node.computationsCompleted,
            node.computationsFailed,
            node.disputesResolved,
            node.active
        );
    }
    
    /**
     * @dev Get all compute nodes.
     * @return Array of compute node addresses
     */
    function getAllComputeNodes() 
        external 
        view 
        returns (address[] memory) 
    {
        return allComputeNodes;
    }
    
    /**
     * @dev Get active compute nodes.
     * @return Array of active compute node addresses
     */
    function getActiveComputeNodes() 
        external 
        view 
        returns (address[] memory) 
    {
        // Count active nodes
        uint256 activeCount = 0;
        for (uint256 i = 0; i < allComputeNodes.length; i++) {
            if (computeNodes[allComputeNodes[i]].active) {
                activeCount++;
            }
        }
        
        // Create result array
        address[] memory activeNodes = new address[](activeCount);
        uint256 index = 0;
        
        for (uint256 i = 0; i < allComputeNodes.length; i++) {
            if (computeNodes[allComputeNodes[i]].active) {
                activeNodes[index] = allComputeNodes[i];
                index++;
            }
        }
        
        return activeNodes;
    }
    
    // ==========================================================================
    // Audit Log
    // ==========================================================================
    
    /**
     * @dev Add an entry to the audit log.
     * @param computationId ID of the computation
     * @param actionType Type of action
     * @param actor Address that performed the action
     * @param details Additional details
     */
    function _addAuditLogEntry(
        bytes32 computationId,
        uint8 actionType,
        address actor,
        string memory details
    ) 
        private 
    {
        AuditLogEntry memory entry = AuditLogEntry({
            computationId: computationId,
            actionType: actionType,
            actor: actor,
            timestamp: block.timestamp,
            details: details
        });
        
        _auditLog[computationId].push(entry);
    }
    
    /**
     * @dev Get audit log for a computation.
     * @param computationId ID of the computation
     * @return Array of audit log entries
     */
    function getAuditLog(bytes32 computationId) 
        external 
        view 
        returns (AuditLogEntry[] memory) 
    {
        return _auditLog[computationId];
    }
    
    // ==========================================================================
    // Admin Functions
    // ==========================================================================
    
    /**
     * @dev Set the Privacy Layer contract address.
     * @param _privacyLayer Address of the Privacy Layer contract
     */
    function setPrivacyLayer(address _privacyLayer)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(_privacyLayer != address(0), "Invalid Privacy Layer address");
        privacyLayer = IPrivacyLayer(_privacyLayer);
    }
    
    /**
     * @dev Pause the contract.
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }
    
    /**
     * @dev Unpause the contract.
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
