// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

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

interface IPrivacyLayer {
    function verifyAccessProof(
        bytes memory proof,
        bytes memory publicSignals,
        uint256 dataVaultId
    ) external view returns (bool);
}

/**
 * @title PrivaSight Access Control
 * @dev Manages granular access control for DataVault NFTs, including
 * rule-based permissions, zero-knowledge proof verification, and
 * time-bound delegation.
 */
contract PrivaSightAccessControl is AccessControl, ReentrancyGuard, Pausable {
    using SafeMath for uint256;
    using ECDSA for bytes32;

    // ==========================================================================
    // Constants
    // ==========================================================================

    bytes32 public constant ACCESS_ADMIN_ROLE = keccak256("ACCESS_ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant PRIVACY_LAYER_ROLE = keccak256("PRIVACY_LAYER_ROLE");

    // Access rule types
    uint8 public constant RULE_TYPE_PURPOSE = 1;     // Research purpose restriction
    uint8 public constant RULE_TYPE_ORGANIZATION = 2; // Organization restriction
    uint8 public constant RULE_TYPE_TIMEBOUND = 3;    // Time-bound access
    uint8 public constant RULE_TYPE_GEOGRAPHY = 4;    // Geographic restriction
    uint8 public constant RULE_TYPE_CUSTOM = 5;       // Custom rule

    // Access status
    uint8 public constant ACCESS_STATUS_NONE = 0;     // No access requested/granted
    uint8 public constant ACCESS_STATUS_REQUESTED = 1; // Access requested
    uint8 public constant ACCESS_STATUS_GRANTED = 2;   // Access granted
    uint8 public constant ACCESS_STATUS_REVOKED = 3;   // Access revoked
    uint8 public constant ACCESS_STATUS_EXPIRED = 4;   // Access expired

    // ==========================================================================
    // State Variables
    // ==========================================================================

    // Core contract references
    IDataVaultNFT public dataVaultNFT;
    IPrivacyLayer public privacyLayer;

    // Access rules
    struct AccessRule {
        uint8 ruleType;
        string condition;         // JSON formatted condition
        bool required;            // Whether this rule is required for access
        bool verificationNeeded;  // Whether verification is needed for this rule
    }

    // Access request
    struct AccessRequest {
        address requester;        // Address requesting access
        uint256 dataVaultId;      // DataVault ID
        uint8 status;             // Current status
        uint256 requestTime;      // When access was requested
        uint256 grantTime;        // When access was granted (if granted)
        uint256 expiryTime;       // When access expires (if granted)
        string purpose;           // Purpose of access
        string[] credentials;     // Credentials provided by requester
        bytes zkProof;            // Zero-knowledge proof (if applicable)
        address approver;         // Address that approved the request
    }

    // Delegated access
    struct AccessDelegation {
        address delegator;        // Address delegating access
        address delegate;         // Address being delegated to
        uint256 dataVaultId;      // DataVault ID
        uint256 startTime;        // When delegation starts
        uint256 endTime;          // When delegation ends
        string[] permissions;     // Array of permission strings
        bool active;              // Whether delegation is active
    }

    // Access grants tracking
    struct AccessGrant {
        uint256 dataVaultId;      // DataVault ID
        address grantee;          // Address granted access
        uint256 startTime;        // When access starts
        uint256 endTime;          // When access ends
        string[] permissions;     // Array of permission strings
        bool active;              // Whether grant is active
    }

    // DataVault access rules
    mapping(uint256 => AccessRule[]) public dataVaultRules;

    // Access requests by requester and DataVault
    mapping(address => mapping(uint256 => AccessRequest[])) private _accessRequests;
    mapping(uint256 => AccessRequest[]) private _vaultAccessRequests;
    mapping(uint256 => uint256) public pendingRequestCount;

    // Active access grants by DataVault
    mapping(uint256 => AccessGrant[]) private _activeGrants;
    mapping(address => AccessGrant[]) private _userGrants;

    // Access delegation tracking
    mapping(address => AccessDelegation[]) private _outgoingDelegations;
    mapping(address => AccessDelegation[]) private _incomingDelegations;
    mapping(uint256 => AccessDelegation[]) private _vaultDelegations;

    // Access rule verification
    mapping(uint256 => mapping(uint8 => address[])) private _ruleVerifiers;

    // Access rule templates
    mapping(uint256 => AccessRule[]) public accessRuleTemplates;
    uint256 public templateCount;

    // Emergency access management
    mapping(uint256 => address[]) public emergencyAccessors;
    mapping(address => bool) public isEmergencyActive;

    // Access logging (for audit)
    struct AccessLog {
        address accessor;
        uint256 dataVaultId;
        uint256 timestamp;
        string accessType; // "grant", "revoke", "delegate", "emergency"
        string metadata;
    }

    mapping(uint256 => AccessLog[]) private _accessLogs;

    // ==========================================================================
    // Events
    // ==========================================================================

    event AccessRuleAdded(
        uint256 indexed dataVaultId,
        uint8 ruleType,
        string condition,
        bool required,
        bool verificationNeeded
    );

    event AccessRuleRemoved(
        uint256 indexed dataVaultId,
        uint8 ruleType,
        string condition
    );

    event AccessRequested(
        address indexed requester,
        uint256 indexed dataVaultId,
        uint256 requestId,
        string purpose
    );

    event AccessGranted(
        address indexed requester,
        uint256 indexed dataVaultId,
        uint256 startTime,
        uint256 endTime,
        address approver
    );

    event AccessRevoked(
        address indexed requester,
        uint256 indexed dataVaultId,
        address revoker
    );

    event AccessDelegated(
        address indexed delegator,
        address indexed delegate,
        uint256 indexed dataVaultId,
        uint256 startTime,
        uint256 endTime
    );

    event DelegationRevoked(
        address indexed delegator,
        address indexed delegate,
        uint256 indexed dataVaultId
    );

    event EmergencyAccessGranted(
        address indexed accessor,
        uint256 indexed dataVaultId
    );

    event EmergencyAccessRevoked(
        address indexed accessor,
        uint256 indexed dataVaultId
    );

    event AccessRuleTemplateCreated(
        uint256 indexed templateId,
        string name,
        string category
    );

    // ==========================================================================
    // Constructor
    // ==========================================================================

    /**
     * @dev Initializes the Access Control contract.
     * @param _dataVaultNFT Address of the DataVault NFT contract
     * @param _privacyLayer Address of the Privacy Layer contract
     */
    constructor(
        address _dataVaultNFT,
        address _privacyLayer
    ) {
        require(_dataVaultNFT != address(0), "Invalid DataVault NFT address");

        dataVaultNFT = IDataVaultNFT(_dataVaultNFT);

        // Privacy layer can be set later if not available at deployment
        if (_privacyLayer != address(0)) {
            privacyLayer = IPrivacyLayer(_privacyLayer);
        }

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ACCESS_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
    }

    // ==========================================================================
    // Access Rule Management
    // ==========================================================================

    /**
     * @dev Add an access rule to a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @param ruleType The type of access rule
     * @param condition JSON formatted condition string
     * @param required Whether this rule is required for access
     * @param verificationNeeded Whether verification is needed for this rule
     */
    function addAccessRule(
        uint256 dataVaultId,
        uint8 ruleType,
        string memory condition,
        bool required,
        bool verificationNeeded
    ) 
        external
        whenNotPaused
        nonReentrant
    {
        require(
            dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(ACCESS_ADMIN_ROLE, msg.sender),
            "Not authorized to modify rules"
        );
        require(ruleType >= RULE_TYPE_PURPOSE && ruleType <= RULE_TYPE_CUSTOM, "Invalid rule type");

        dataVaultRules[dataVaultId].push(AccessRule({
            ruleType: ruleType,
            condition: condition,
            required: required,
            verificationNeeded: verificationNeeded
        }));

        emit AccessRuleAdded(dataVaultId, ruleType, condition, required, verificationNeeded);
    }

    /**
     * @dev Remove an access rule from a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @param ruleIndex The index of the rule to remove
     */
    function removeAccessRule(
        uint256 dataVaultId,
        uint256 ruleIndex
    ) 
        external
        whenNotPaused
        nonReentrant
    {
        require(
            dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(ACCESS_ADMIN_ROLE, msg.sender),
            "Not authorized to modify rules"
        );
        require(ruleIndex < dataVaultRules[dataVaultId].length, "Rule index out of bounds");

        AccessRule storage rule = dataVaultRules[dataVaultId][ruleIndex];
        uint8 ruleType = rule.ruleType;
        string memory condition = rule.condition;

        if (ruleIndex < dataVaultRules[dataVaultId].length - 1) {
            dataVaultRules[dataVaultId][ruleIndex] = dataVaultRules[dataVaultId][dataVaultRules[dataVaultId].length - 1];
        }
        dataVaultRules[dataVaultId].pop();

        emit AccessRuleRemoved(dataVaultId, ruleType, condition);
    }

    /**
     * @dev Get all access rules for a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @return Array of access rules
     */
    function getAccessRules(uint256 dataVaultId) external view returns (AccessRule[] memory) {
        return dataVaultRules[dataVaultId];
    }

    /**
     * @dev Add a rule verifier for a specific rule type.
     * @param dataVaultId The ID of the DataVault NFT
     * @param ruleType The type of rule to verify
     * @param verifier Address of the verifier
     */
    function addRuleVerifier(
        uint256 dataVaultId,
        uint8 ruleType,
        address verifier
    ) 
        external
        whenNotPaused
    {
        require(
            dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(ACCESS_ADMIN_ROLE, msg.sender),
            "Not authorized to add verifier"
        );
        _ruleVerifiers[dataVaultId][ruleType].push(verifier);
    }

    /**
     * @dev Remove a rule verifier.
     * @param dataVaultId The ID of the DataVault NFT
     * @param ruleType The type of rule
     * @param verifierIndex The index of the verifier to remove
     */
    function removeRuleVerifier(
        uint256 dataVaultId,
        uint8 ruleType,
        uint256 verifierIndex
    ) 
        external
        whenNotPaused
    {
        require(
            dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(ACCESS_ADMIN_ROLE, msg.sender),
            "Not authorized to remove verifier"
        );
        require(verifierIndex < _ruleVerifiers[dataVaultId][ruleType].length, "Verifier index out of bounds");

        if (verifierIndex < _ruleVerifiers[dataVaultId][ruleType].length - 1) {
            _ruleVerifiers[dataVaultId][ruleType][verifierIndex] = 
                _ruleVerifiers[dataVaultId][ruleType][_ruleVerifiers[dataVaultId][ruleType].length - 1];
        }
        _ruleVerifiers[dataVaultId][ruleType].pop();
    }

    /**
     * @dev Get all verifiers for a specific rule type.
     * @param dataVaultId The ID of the DataVault NFT
     * @param ruleType The type of rule
     * @return Array of verifier addresses
     */
    function getRuleVerifiers(
        uint256 dataVaultId,
        uint8 ruleType
    ) 
        external
        view
        returns (address[] memory) 
    {
        return _ruleVerifiers[dataVaultId][ruleType];
    }

    /**
     * @dev Create an access rule template.
     * @param name Name of the template
     * @param category Category of the template (e.g., "medical", "financial")
     * @param rules Array of access rules
     * @return templateId ID of the created template
     */
    function createAccessRuleTemplate(
        string memory name,
        string memory category,
        AccessRule[] memory rules
    ) 
        external
        onlyRole(ACCESS_ADMIN_ROLE)
        returns (uint256)
    {
        templateCount++;
        uint256 templateId = templateCount;

        for (uint256 i = 0; i < rules.length; i++) {
            accessRuleTemplates[templateId].push(rules[i]);
        }

        emit AccessRuleTemplateCreated(templateId, name, category);
        return templateId;
    }

    /**
     * @dev Apply an access rule template to a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @param templateId The ID of the template to apply
     */
    function applyAccessRuleTemplate(
        uint256 dataVaultId,
        uint256 templateId
    ) 
        external
        whenNotPaused
        nonReentrant
    {
        require(
            dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(ACCESS_ADMIN_ROLE, msg.sender),
            "Not authorized to apply template"
        );
        require(templateId <= templateCount && templateId > 0, "Template does not exist");

        for (uint256 i = 0; i < accessRuleTemplates[templateId].length; i++) {
            AccessRule storage rule = accessRuleTemplates[templateId][i];
            dataVaultRules[dataVaultId].push(AccessRule({
                ruleType: rule.ruleType,
                condition: rule.condition,
                required: rule.required,
                verificationNeeded: rule.verificationNeeded
            }));
            emit AccessRuleAdded(dataVaultId, rule.ruleType, rule.condition, rule.required, rule.verificationNeeded);
        }
    }

    // ==========================================================================
    // Access Request and Approval
    // ==========================================================================

    /**
     * @dev Request access to a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @param purpose Purpose of access request
     * @param credentials Array of credential strings
     * @param zkProof Zero-knowledge proof bytes (if applicable)
     * @return requestId Index of the created request
     */
    function requestAccess(
        uint256 dataVaultId,
        string memory purpose,
        string[] memory credentials,
        bytes memory zkProof
    ) 
        external
        whenNotPaused
        nonReentrant
        returns (uint256)
    {
        AccessRequest memory request = AccessRequest({
            requester: msg.sender,
            dataVaultId: dataVaultId,
            status: ACCESS_STATUS_REQUESTED,
            requestTime: block.timestamp,
            grantTime: 0,
            expiryTime: 0,
            purpose: purpose,
            credentials: credentials,
            zkProof: zkProof,
            approver: address(0)
        });

        _accessRequests[msg.sender][dataVaultId].push(request);
        _vaultAccessRequests[dataVaultId].push(request);
        pendingRequestCount[dataVaultId]++;

        uint256 requestId = _vaultAccessRequests[dataVaultId].length - 1;
        emit AccessRequested(msg.sender, dataVaultId, requestId, purpose);
        return requestId;
    }

    /**
     * @dev Grant access to a DataVault NFT based on a request.
     * @param dataVaultId The ID of the DataVault NFT
     * @param requestId The ID of the request
     * @param durationSeconds Duration of access in seconds
     * @param permissions Array of permission strings
     */
    function grantAccess(
        uint256 dataVaultId,
        uint256 requestId,
        uint256 durationSeconds,
        string[] memory permissions
    ) 
        external
        whenNotPaused
        nonReentrant
    {
        require(
            dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(ACCESS_ADMIN_ROLE, msg.sender),
            "Not authorized to grant access"
        );
        require(requestId < _vaultAccessRequests[dataVaultId].length, "Request does not exist");

        AccessRequest storage request = _vaultAccessRequests[dataVaultId][requestId];
        require(request.status == ACCESS_STATUS_REQUESTED, "Request not in requestable status");

        request.status = ACCESS_STATUS_GRANTED;
        request.grantTime = block.timestamp;
        request.expiryTime = block.timestamp + durationSeconds;
        request.approver = msg.sender;

        pendingRequestCount[dataVaultId]--;

        AccessGrant memory grant = AccessGrant({
            dataVaultId: dataVaultId,
            grantee: request.requester,
            startTime: block.timestamp,
            endTime: block.timestamp + durationSeconds,
            permissions: permissions,
            active: true
        });

        _activeGrants[dataVaultId].push(grant);
        _userGrants[request.requester].push(grant);

        _logAccess(
            request.requester,
            dataVaultId,
            "grant",
            string(abi.encodePacked("Duration: ", _uintToString(durationSeconds), " seconds"))
        );

        emit AccessGranted(request.requester, dataVaultId, block.timestamp, block.timestamp + durationSeconds, msg.sender);
    }

    /**
     * @dev Revoke access to a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @param grantee Address of the grantee
     */
    function revokeAccess(
        uint256 dataVaultId,
        address grantee
    ) 
        external
        whenNotPaused
        nonReentrant
    {
        require(
            dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(ACCESS_ADMIN_ROLE, msg.sender),
            "Not authorized to revoke access"
        );

        bool found = false;
        for (uint256 i = 0; i < _activeGrants[dataVaultId].length; i++) {
            if (_activeGrants[dataVaultId][i].grantee == grantee && _activeGrants[dataVaultId][i].active) {
                _activeGrants[dataVaultId][i].active = false;
                found = true;
            }
        }
        require(found, "No active grants found for grantee");

        for (uint256 i = 0; i < _vaultAccessRequests[dataVaultId].length; i++) {
            if (_vaultAccessRequests[dataVaultId][i].requester == grantee && 
                _vaultAccessRequests[dataVaultId][i].status == ACCESS_STATUS_GRANTED) {
                _vaultAccessRequests[dataVaultId][i].status = ACCESS_STATUS_REVOKED;
            }
        }

        _logAccess(grantee, dataVaultId, "revoke", "Access explicitly revoked");
        emit AccessRevoked(grantee, dataVaultId, msg.sender);
    }

    /**
     * @dev Check if an address has access to a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @param accessor Address to check
     * @return hasAccess Whether the address has access
     * @return expiryTime When the access expires (0 if no access)
     */
    function checkAccess(
        uint256 dataVaultId,
        address accessor
    ) 
        external
        view
        returns (bool hasAccess, uint256 expiryTime)
    {
        if (dataVaultNFT.ownerOf(dataVaultId) == accessor) {
            return (true, type(uint256).max);
        }
        if (_hasEmergencyAccess(accessor, dataVaultId)) {
            return (true, type(uint256).max);
        }
        for (uint256 i = 0; i < _activeGrants[dataVaultId].length; i++) {
            AccessGrant storage grant = _activeGrants[dataVaultId][i];
            if (grant.grantee == accessor && grant.active && grant.endTime > block.timestamp) {
                return (true, grant.endTime);
            }
        }
        for (uint256 i = 0; i < _vaultDelegations[dataVaultId].length; i++) {
            AccessDelegation storage delegation = _vaultDelegations[dataVaultId][i];
            if (delegation.delegate == accessor && delegation.active && delegation.endTime > block.timestamp) {
                return (true, delegation.endTime);
            }
        }
        return (false, 0);
    }

    /**
     * @dev Get all access requests for a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @return Array of access requests
     */
    function getAccessRequests(uint256 dataVaultId) external view returns (AccessRequest[] memory) {
        return _vaultAccessRequests[dataVaultId];
    }

    /**
     * @dev Get all active access grants for a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @return Array of active access grants
     */
    function getActiveGrants(uint256 dataVaultId) external view returns (AccessGrant[] memory) {
        return _activeGrants[dataVaultId];
    }

    /**
     * @dev Get all access grants for a user.
     * @param user Address of the user
     * @return Array of access grants
     */
    function getUserGrants(address user) external view returns (AccessGrant[] memory) {
        return _userGrants[user];
    }

    // ==========================================================================
    // Access Delegation
    // ==========================================================================

    /**
     * @dev Delegate access to another address.
     * @param delegate Address to delegate access to
     * @param dataVaultId The ID of the DataVault NFT
     * @param durationSeconds Duration of delegation in seconds
     * @param permissions Array of permission strings
     */
    function delegateAccess(
        address delegate,
        uint256 dataVaultId,
        uint256 durationSeconds,
        string[] memory permissions
    ) 
        external
        whenNotPaused
        nonReentrant
    {
        (bool hasAccess, uint256 expiryTime) = this.checkAccess(dataVaultId, msg.sender);
        require(hasAccess, "Caller does not have access to delegate");

        uint256 endTime = block.timestamp + durationSeconds;
        if (expiryTime < type(uint256).max) {
            endTime = endTime > expiryTime ? expiryTime : endTime;
        }

        AccessDelegation memory delegation = AccessDelegation({
            delegator: msg.sender,
            delegate: delegate,
            dataVaultId: dataVaultId,
            startTime: block.timestamp,
            endTime: endTime,
            permissions: permissions,
            active: true
        });

        _outgoingDelegations[msg.sender].push(delegation);
        _incomingDelegations[delegate].push(delegation);
        _vaultDelegations[dataVaultId].push(delegation);

        _logAccess(
            delegate,
            dataVaultId,
            "delegate",
            string(abi.encodePacked("Delegated by: ", _addressToString(msg.sender)))
        );
        emit AccessDelegated(msg.sender, delegate, dataVaultId, block.timestamp, endTime);
    }

    /**
     * @dev Revoke a delegation.
     * @param delegate Address the access was delegated to
     * @param dataVaultId The ID of the DataVault NFT
     */
    function revokeDelegation(
        address delegate,
        uint256 dataVaultId
    ) 
        external
        whenNotPaused
        nonReentrant
    {
        bool found = false;
        for (uint256 i = 0; i < _outgoingDelegations[msg.sender].length; i++) {
            if (_outgoingDelegations[msg.sender][i].delegate == delegate && 
                _outgoingDelegations[msg.sender][i].dataVaultId == dataVaultId &&
                _outgoingDelegations[msg.sender][i].active) {
                _outgoingDelegations[msg.sender][i].active = false;
                found = true;
            }
        }
        for (uint256 i = 0; i < _vaultDelegations[dataVaultId].length; i++) {
            if (_vaultDelegations[dataVaultId][i].delegator == msg.sender && 
                _vaultDelegations[dataVaultId][i].delegate == delegate &&
                _vaultDelegations[dataVaultId][i].active) {
                _vaultDelegations[dataVaultId][i].active = false;
            }
        }
        for (uint256 i = 0; i < _incomingDelegations[delegate].length; i++) {
            if (_incomingDelegations[delegate][i].delegator == msg.sender && 
                _incomingDelegations[delegate][i].dataVaultId == dataVaultId &&
                _incomingDelegations[delegate][i].active) {
                _incomingDelegations[delegate][i].active = false;
            }
        }
        require(found, "No active delegation found");

        _logAccess(
            delegate,
            dataVaultId,
            "revoke_delegation",
            string(abi.encodePacked("Revoked by delegator: ", _addressToString(msg.sender)))
        );
        emit DelegationRevoked(msg.sender, delegate, dataVaultId);
    }

    /**
     * @dev Get all outgoing delegations for an address.
     * @param delegator Address of the delegator
     * @return Array of outgoing delegations
     */
    function getOutgoingDelegations(address delegator) external view returns (AccessDelegation[] memory) {
        return _outgoingDelegations[delegator];
    }

    /**
     * @dev Get all incoming delegations for an address.
     * @param delegate Address of the delegate
     * @return Array of incoming delegations
     */
    function getIncomingDelegations(address delegate) external view returns (AccessDelegation[] memory) {
        return _incomingDelegations[delegate];
    }

    /**
     * @dev Get all delegations for a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @return Array of delegations
     */
    function getVaultDelegations(uint256 dataVaultId) external view returns (AccessDelegation[] memory) {
        return _vaultDelegations[dataVaultId];
    }

    // ==========================================================================
    // Emergency Access
    // ==========================================================================

    /**
     * @dev Add an emergency accessor for a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @param accessor Address to add as emergency accessor
     */
    function addEmergencyAccessor(
        uint256 dataVaultId,
        address accessor
    ) 
        external
        whenNotPaused
    {
        require(
            dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(ACCESS_ADMIN_ROLE, msg.sender),
            "Not authorized to add emergency accessor"
        );
        emergencyAccessors[dataVaultId].push(accessor);
        emit EmergencyAccessGranted(accessor, dataVaultId);
    }

    /**
     * @dev Remove an emergency accessor.
     * @param dataVaultId The ID of the DataVault NFT
     * @param accessorIndex The index of the accessor to remove
     */
    function removeEmergencyAccessor(
        uint256 dataVaultId,
        uint256 accessorIndex
    ) 
        external
        whenNotPaused
    {
        require(
            dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(ACCESS_ADMIN_ROLE, msg.sender),
            "Not authorized to remove emergency accessor"
        );
        require(accessorIndex < emergencyAccessors[dataVaultId].length, "Accessor index out of bounds");

        address accessor = emergencyAccessors[dataVaultId][accessorIndex];
        if (accessorIndex < emergencyAccessors[dataVaultId].length - 1) {
            emergencyAccessors[dataVaultId][accessorIndex] = 
                emergencyAccessors[dataVaultId][emergencyAccessors[dataVaultId].length - 1];
        }
        emergencyAccessors[dataVaultId].pop();
        emit EmergencyAccessRevoked(accessor, dataVaultId);
    }

    /**
     * @dev Activate emergency access.
     * @param reason Reason for emergency access
     */
    function activateEmergencyAccess(string memory reason) 
        external
        onlyRole(ACCESS_ADMIN_ROLE)
    {
        isEmergencyActive[msg.sender] = true;
        _logAccess(msg.sender, 0, "emergency_activate", reason);
    }

    /**
     * @dev Deactivate emergency access.
     */
    function deactivateEmergencyAccess() 
        external
        onlyRole(ACCESS_ADMIN_ROLE)
    {
        isEmergencyActive[msg.sender] = false;
        _logAccess(msg.sender, 0, "emergency_deactivate", "");
    }

    /**
     * @dev Check if an address has emergency access to a DataVault NFT.
     * @param accessor Address to check
     * @param dataVaultId The ID of the DataVault NFT
     * @return Whether the address has emergency access
     */
    function _hasEmergencyAccess(address accessor, uint256 dataVaultId) internal view returns (bool) {
        for (uint256 i = 0; i < emergencyAccessors[dataVaultId].length; i++) {
            if (emergencyAccessors[dataVaultId][i] == accessor && isEmergencyActive[accessor]) {
                return true;
            }
        }
        return hasRole(ACCESS_ADMIN_ROLE, accessor) && isEmergencyActive[accessor];
    }

    /**
     * @dev Get all emergency accessors for a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @return Array of emergency accessor addresses
     */
    function getEmergencyAccessors(uint256 dataVaultId) external view returns (address[] memory) {
        return emergencyAccessors[dataVaultId];
    }

    // ==========================================================================
    // ZKP Verification
    // ==========================================================================

    /**
     * @dev Set the Privacy Layer contract address.
     * @param _privacyLayer Address of the Privacy Layer contract
     */
    function setPrivacyLayer(address _privacyLayer)
        external
        onlyRole(ACCESS_ADMIN_ROLE)
    {
        require(_privacyLayer != address(0), "Invalid Privacy Layer address");
        privacyLayer = IPrivacyLayer(_privacyLayer);
    }

    /**
     * @dev Verify a ZKP for access to a DataVault NFT.
     * @param proof ZKP proof bytes
     * @param publicSignals Public signals for the proof
     * @param dataVaultId The ID of the DataVault NFT
     * @return Whether the proof is valid
     */
    function verifyProof(
        bytes memory proof,
        bytes memory publicSignals,
        uint256 dataVaultId
    ) 
        external
        view
        returns (bool)
    {
        require(address(privacyLayer) != address(0), "Privacy Layer not set");
        return privacyLayer.verifyAccessProof(proof, publicSignals, dataVaultId);
    }

    // ==========================================================================
    // Access Logs
    // ==========================================================================

    /**
     * @dev Log an access event for audit purposes.
     * @param accessor Address accessing the data
     * @param dataVaultId The ID of the DataVault NFT
     * @param accessType Type of access event
     * @param metadata Additional metadata
     */
    function _logAccess(
        address accessor,
        uint256 dataVaultId,
        string memory accessType,
        string memory metadata
    ) 
        internal
    {
        AccessLog memory log = AccessLog({
            accessor: accessor,
            dataVaultId: dataVaultId,
            timestamp: block.timestamp,
            accessType: accessType,
            metadata: metadata
        });
        _accessLogs[dataVaultId].push(log);
    }

    /**
     * @dev Get access logs for a DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @return Array of access logs
     */
    function getAccessLogs(uint256 dataVaultId) 
        external
        view
        returns (AccessLog[] memory) 
    {
        require(
            dataVaultNFT.ownerOf(dataVaultId) == msg.sender || 
            hasRole(ACCESS_ADMIN_ROLE, msg.sender) ||
            hasRole(VERIFIER_ROLE, msg.sender),
            "Not authorized to view logs"
        );
        return _accessLogs[dataVaultId];
    }

    // ==========================================================================
    // Admin Functions
    // ==========================================================================

    /**
     * @dev Pause the contract.
     */
    function pause() external onlyRole(ACCESS_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @dev Unpause the contract.
     */
    function unpause() external onlyRole(ACCESS_ADMIN_ROLE) {
        _unpause();
    }

    // ==========================================================================
    // Utility Functions
    // ==========================================================================

    /**
     * @dev Convert an address to a string.
     * @param _addr Address to convert
     * @return String representation of the address
     */
    function _addressToString(address _addr) internal pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(_addr)));
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(42);
        str[0] = '0';
        str[1] = 'x';
        for (uint256 i = 0; i < 20; i++) {
            str[2+i*2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3+i*2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }
        return string(str);
    }

    /**
     * @dev Convert a uint to a string.
     * @param _i Uint to convert
     * @return String representation of the uint
     */
    function _uintToString(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 length;
        while (j != 0) {
            length++;
            j /= 10;
        }
        bytes memory bstr = new bytes(length);
        uint256 k = length;
        while (_i != 0) {
            k = k-1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }
}
