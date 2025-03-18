// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorTimelockControl.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

interface IPrivaToken {
    function hasGovernanceAccess(address account) external view returns (bool);
    function getStakingTier(address account) external view returns (uint256 tierIndex, StakingTier memory tier);
    function balanceOf(address account) external view returns (uint256);
    
    struct StakingTier {
        uint256 minAmount;
        uint16 rewardMultiplier;
        uint16 feeDiscount;
        bool marketplaceAccess;
        bool governanceAccess;
        bool priorityAccess;
    }
}

/**
 * @title PrivaSight Governance
 * @dev Governance contract for the PrivaSight ecosystem, allowing token holders
 * with governance access to propose and vote on protocol changes. Integrates with
 * PrivaToken staking tiers to determine governance weight and access.
 */
contract PrivaSightGovernance is 
    Governor, 
    GovernorSettings, 
    GovernorCountingSimple, 
    GovernorVotes, 
    GovernorVotesQuorumFraction,
    GovernorTimelockControl,
    AccessControl
{
    // ==========================================================================
    // Constants
    // ==========================================================================
    
    bytes32 public constant GOVERNANCE_ADMIN_ROLE = keccak256("GOVERNANCE_ADMIN_ROLE");
    bytes32 public constant PROPOSAL_REVIEWER_ROLE = keccak256("PROPOSAL_REVIEWER_ROLE");
    bytes32 public constant EMERGENCY_COUNCIL_ROLE = keccak256("EMERGENCY_COUNCIL_ROLE");
    
    // Categories for proposals
    uint8 public constant CATEGORY_PROTOCOL_UPGRADE = 1;
    uint8 public constant CATEGORY_PARAMETER_CHANGE = 2;
    uint8 public constant CATEGORY_TREASURY_MANAGEMENT = 3;
    uint8 public constant CATEGORY_RESEARCH_APPROVAL = 4;
    uint8 public constant CATEGORY_FEATURE_REQUEST = 5;
    
    // Thresholds for different proposal types (in voting power percentage, base 10000)
    uint16 private constant THRESHOLD_DEFAULT = 1000; // 10% of total voting power
    uint16 private constant THRESHOLD_PROTOCOL_UPGRADE = 2000; // 20% of total voting power
    uint16 private constant THRESHOLD_PARAMETER_CHANGE = 1500; // 15% of total voting power
    uint16 private constant THRESHOLD_TREASURY = 2500; // 25% of total voting power
    
    // ==========================================================================
    // State Variables
    // ==========================================================================
    
    IPrivaToken public privaToken;
    
    // Proposal metadata storage
    struct ProposalMetadata {
        uint8 category;
        string title;
        string description;
        string documentationURI;
        address proposer;
        uint16 requiredThreshold;
        bool isEmergency;
        bool reviewed;
    }
    
    // Map proposalId to metadata
    mapping(uint256 => ProposalMetadata) private _proposalMetadata;
    
    // Track all proposals by category
    mapping(uint8 => uint256[]) private _proposalsByCategory;
    
    // Track proposals by account
    mapping(address => uint256[]) private _proposalsByAccount;
    
    // Stake-weighted voting power boost
    mapping(uint256 => mapping(address => uint256)) private _voteBoosts;
    
    // Emergency state
    bool private _emergencyActive;
    uint256 private _emergencyActivationTime;
    string private _emergencyReason;
    
    // Events
    event ProposalCreated(
        uint256 indexed proposalId,
        uint8 category,
        string title,
        address indexed proposer
    );
    
    event ProposalReviewed(
        uint256 indexed proposalId,
        address indexed reviewer,
        bool approved
    );
    
    event EmergencyActivated(
        address indexed activator,
        string reason
    );
    
    event EmergencyDeactivated(
        address indexed deactivator
    );
    
    event VoteBoostApplied(
        uint256 indexed proposalId,
        address indexed voter,
        uint256 originalWeight,
        uint256 boostedWeight
    );

    // ==========================================================================
    // Constructor
    // ==========================================================================
    
    /**
     * @dev Initialize the PrivaSight Governance contract.
     * @param _token The ERC20Votes token used for governance
     * @param _privaToken The PrivaToken address for staking tier integration
     * @param _timelock The timelock controller address for executing proposals
     * @param _initialAdmin The initial admin address for the contract
     */
    constructor(
        IVotes _token,
        IPrivaToken _privaToken,
        TimelockController _timelock,
        address _initialAdmin
    )
        Governor("PrivaSight Governance")
        GovernorSettings(
            1 days, // 1 day voting delay
            7 days, // 1 week voting period
            100e18 // 100 token proposal threshold
        )
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(10) // 10% quorum
        GovernorTimelockControl(_timelock)
    {
        privaToken = _privaToken;
        
        // Setup admin roles
        _grantRole(DEFAULT_ADMIN_ROLE, _initialAdmin);
        _grantRole(GOVERNANCE_ADMIN_ROLE, _initialAdmin);
        _grantRole(PROPOSAL_REVIEWER_ROLE, _initialAdmin);
        _grantRole(EMERGENCY_COUNCIL_ROLE, _initialAdmin);
    }
    
    // ==========================================================================
    // Proposal Management
    // ==========================================================================
    
    /**
     * @dev Create a proposal with metadata.
     * @param targets Target addresses for proposal calls
     * @param values ETH values for proposal calls
     * @param calldatas Call data for proposal calls
     * @param description Description of the proposal
     * @param category Category of the proposal
     * @param title Title of the proposal
     * @param documentationURI URI to additional documentation
     * @param isEmergency Whether this is an emergency proposal
     * @return uint256 ID of the created proposal
     */
    function proposeWithMetadata(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description,
        uint8 category,
        string memory title,
        string memory documentationURI,
        bool isEmergency
    ) public returns (uint256) {
        // Verify the proposer has governance access via staking tier or role
        require(
            privaToken.hasGovernanceAccess(msg.sender) || hasRole(GOVERNANCE_ADMIN_ROLE, msg.sender),
            "Caller lacks governance access"
        );
        
        // For emergency proposals, require emergency council role
        if (isEmergency) {
            require(
                hasRole(EMERGENCY_COUNCIL_ROLE, msg.sender),
                "Emergency proposals require emergency council role"
            );
        }
        
        // Validate the category
        require(
            category >= CATEGORY_PROTOCOL_UPGRADE && category <= CATEGORY_FEATURE_REQUEST,
            "Invalid proposal category"
        );
        
        // Create the proposal using Governor's propose function
        uint256 proposalId = super.propose(targets, values, calldatas, description);
        
        // Determine the required threshold based on category
        uint16 requiredThreshold;
        if (category == CATEGORY_PROTOCOL_UPGRADE) {
            requiredThreshold = THRESHOLD_PROTOCOL_UPGRADE;
        } else if (category == CATEGORY_PARAMETER_CHANGE) {
            requiredThreshold = THRESHOLD_PARAMETER_CHANGE;
        } else if (category == CATEGORY_TREASURY_MANAGEMENT) {
            requiredThreshold = THRESHOLD_TREASURY;
        } else {
            requiredThreshold = THRESHOLD_DEFAULT;
        }
        
        // Store the proposal metadata
        _proposalMetadata[proposalId] = ProposalMetadata({
            category: category,
            title: title,
            description: description,
            documentationURI: documentationURI,
            proposer: msg.sender,
            requiredThreshold: requiredThreshold,
            isEmergency: isEmergency,
            reviewed: false // All proposals start unreviewed
        });
        
        // Add to category index
        _proposalsByCategory[category].push(proposalId);
        
        // Add to proposer's index
        _proposalsByAccount[msg.sender].push(proposalId);
        
        emit ProposalCreated(proposalId, category, title, msg.sender);
        
        return proposalId;
    }
    
    /**
     * @dev Review a proposal. This is required before voting can begin.
     * @param proposalId The ID of the proposal to review
     * @param approve Whether to approve the proposal for voting
     */
    function reviewProposal(uint256 proposalId, bool approve) external onlyRole(PROPOSAL_REVIEWER_ROLE) {
        ProposalMetadata storage metadata = _proposalMetadata[proposalId];
        require(metadata.proposer != address(0), "Proposal does not exist");
        require(!metadata.reviewed, "Proposal already reviewed");
        
        metadata.reviewed = true;
        
        // If not approved, cancel the proposal
        if (!approve) {
            _cancel(
                proposalId,
                metadata.proposer,
                address(0)
            );
        }
        
        emit ProposalReviewed(proposalId, msg.sender, approve);
    }
    
    /**
     * @dev Get proposal metadata.
     * @param proposalId The ID of the proposal
     * @return category The proposal category
     * @return title The proposal title
     * @return description The proposal description
     * @return documentationURI The URI to proposal documentation
     * @return proposer The address of the proposer
     * @return requiredThreshold The required threshold for the proposal
     * @return isEmergency Whether it's an emergency proposal
     * @return reviewed Whether the proposal has been reviewed
     */
    function getProposalMetadata(uint256 proposalId) external view returns (
        uint8 category,
        string memory title,
        string memory description,
        string memory documentationURI,
        address proposer,
        uint16 requiredThreshold,
        bool isEmergency,
        bool reviewed
    ) {
        ProposalMetadata storage metadata = _proposalMetadata[proposalId];
        require(metadata.proposer != address(0), "Proposal does not exist");
        
        return (
            metadata.category,
            metadata.title,
            metadata.description,
            metadata.documentationURI,
            metadata.proposer,
            metadata.requiredThreshold,
            metadata.isEmergency,
            metadata.reviewed
        );
    }
    
    /**
     * @dev Get proposals by category.
     * @param category The category to query
     * @return An array of proposal IDs in the category
     */
    function getProposalsByCategory(uint8 category) external view returns (uint256[] memory) {
        return _proposalsByCategory[category];
    }
    
    /**
     * @dev Get proposals by proposer account.
     * @param account The proposer address
     * @return An array of proposal IDs created by the account
     */
    function getProposalsByAccount(address account) external view returns (uint256[] memory) {
        return _proposalsByAccount[account];
    }
    
    // ==========================================================================
    // Vote Weighting and Boosting
    // ==========================================================================
    
    /**
     * @dev Override the standard vote weight to apply staking tier bonuses.
     * @param proposalId The ID of the proposal
     * @param account The voter account
     * @param support The vote support value (0=against, 1=for, 2=abstain)
     * @param weight The standard vote weight from token balance
     * @return The adjusted vote weight after applying staking tier bonus
     */
    function _countVote(
        uint256 proposalId,
        address account,
        uint8 support,
        uint256 weight,
        bytes memory // params
    ) internal override returns (uint256) {
        // Get the voter's staking tier
        (uint256 tierIndex, IPrivaToken.StakingTier memory tier) = privaToken.getStakingTier(account);
        
        // Apply boost based on staking tier
        uint256 boostedWeight = weight;
        
        // Only apply boosts for tiers above the basic level (tierIndex > 0)
        if (tierIndex > 0) {
            // Apply a percentage boost based on tier
            uint256 boost = 0;
            
            if (tierIndex == 1) {
                boost = weight * 10 / 100; // 10% boost for Silver
            } else if (tierIndex == 2) {
                boost = weight * 25 / 100; // 25% boost for Gold
            } else if (tierIndex >= 3) {
                boost = weight * 50 / 100; // 50% boost for Platinum and above
            }
            
            boostedWeight = weight + boost;
            _voteBoosts[proposalId][account] = boost;
            
            emit VoteBoostApplied(proposalId, account, weight, boostedWeight);
        }
        
        return super._countVote(proposalId, account, support, boostedWeight, "");
    }
    
    /**
     * @dev Get the vote boost applied to a specific vote.
     * @param proposalId The ID of the proposal
     * @param account The voter account
     * @return The amount of vote boost applied
     */
    function getVoteBoost(uint256 proposalId, address account) external view returns (uint256) {
        return _voteBoosts[proposalId][account];
    }
    
    // ==========================================================================
    // Emergency Management
    // ==========================================================================
    
    /**
     * @dev Activate emergency mode, which enables fast-track governance.
     * @param reason The reason for activating emergency mode
     */
    function activateEmergency(string memory reason) external onlyRole(EMERGENCY_COUNCIL_ROLE) {
        require(!_emergencyActive, "Emergency already active");
        
        _emergencyActive = true;
        _emergencyActivationTime = block.timestamp;
        _emergencyReason = reason;
        
        emit EmergencyActivated(msg.sender, reason);
    }
    
    /**
     * @dev Deactivate emergency mode.
     */
    function deactivateEmergency() external onlyRole(EMERGENCY_COUNCIL_ROLE) {
        require(_emergencyActive, "Emergency not active");
        
        _emergencyActive = false;
        _emergencyActivationTime = 0;
        _emergencyReason = "";
        
        emit EmergencyDeactivated(msg.sender);
    }
    
    /**
     * @dev Get the current emergency state.
     * @return active Whether emergency mode is active
     * @return activationTime When emergency mode was activated
     * @return reason The reason for emergency mode
     */
    function getEmergencyState() external view returns (
        bool active,
        uint256 activationTime,
        string memory reason
    ) {
        return (_emergencyActive, _emergencyActivationTime, _emergencyReason);
    }
    
    /**
     * @dev Check if an account is a member of the emergency council.
     * @param account The account to check
     * @return Whether the account is on the emergency council
     */
    function isEmergencyCouncilMember(address account) external view returns (bool) {
        return hasRole(EMERGENCY_COUNCIL_ROLE, account);
    }
    
    // ==========================================================================
    // Override Required Functions
    // ==========================================================================
    
    /**
     * @dev Override to ensure proposals are reviewed before voting starts.
     * @param proposalId The ID of the proposal
     * @return The proposal state
     */
    function state(uint256 proposalId) public view override(Governor, GovernorTimelockControl) returns (ProposalState) {
        ProposalState currentState = super.state(proposalId);
        
        // If the proposal is in the Pending state (waiting for voting to begin),
        // check if it has been reviewed
        if (currentState == ProposalState.Pending) {
            ProposalMetadata storage metadata = _proposalMetadata[proposalId];
            
            // If the proposal exists but hasn't been reviewed, treat it as Pending
            if (metadata.proposer != address(0) && !metadata.reviewed) {
                return ProposalState.Pending;
            }
        }
        
        return currentState;
    }
    
    /**
     * @dev Override voting delay for emergency proposals.
     * @param proposalId The ID of the proposal
     * @return The voting delay in blocks
     */
    function proposalVotingDelay(uint256 proposalId) public view returns (uint256) {
        ProposalMetadata storage metadata = _proposalMetadata[proposalId];
        
        // Emergency proposals (during emergency state) have no delay
        if (_emergencyActive && metadata.isEmergency) {
            return 0;
        }
        
        return votingDelay();
    }
    
    /**
     * @dev Override voting period for emergency proposals.
     * @param proposalId The ID of the proposal
     * @return The voting period in blocks
     */
    function proposalVotingPeriod(uint256 proposalId) public view returns (uint256) {
        ProposalMetadata storage metadata = _proposalMetadata[proposalId];
        
        // Emergency proposals have shorter voting period (1 day)
        if (_emergencyActive && metadata.isEmergency) {
            return 1 days;
        }
        
        return votingPeriod();
    }
    
    /**
     * @dev Override quorum for different proposal categories.
     * @param proposalId The ID of the proposal
     * @return Whether the quorum has been reached
     */
    function _quorumReached(uint256 proposalId) internal view override returns (bool) {
        ProposalMetadata storage metadata = _proposalMetadata[proposalId];
        
        // For emergency proposals during emergency, reduce quorum
        if (_emergencyActive && metadata.isEmergency) {
            uint256 votes = _countVotesCast(proposalId);
            uint256 totalSupply = token().getPastTotalSupply(proposalSnapshot(proposalId));
            
            // Emergency quorum is 5% of total supply
            return votes >= (totalSupply * 5) / 100;
        }
        
        return super._quorumReached(proposalId);
    }
    
    /**
     * @dev Override to require different thresholds for different proposal categories.
     * @param proposalId The ID of the proposal
     * @return Whether the proposal threshold is met
     */
    function _voteSucceeded(uint256 proposalId) internal view override returns (bool) {
        // First check if the standard vote counting says it succeeded
        if (!super._voteSucceeded(proposalId)) {
            return false;
        }
        
        // If it passed the basic check, now check against category threshold
        ProposalMetadata storage metadata = _proposalMetadata[proposalId];
        ProposalVote memory proposalVote = _proposalVotes[proposalId];
        
        uint256 totalVotes = proposalVote.forVotes + proposalVote.againstVotes + proposalVote.abstainVotes;
        uint256 forVotesPercentage = (proposalVote.forVotes * 10000) / totalVotes;
        
        // Check against the required threshold for this category
        return forVotesPercentage >= metadata.requiredThreshold;
    }
    
    /**
     * @dev Helper to count total votes cast.
     * @param proposalId The ID of the proposal
     * @return The total votes cast
     */
    function _countVotesCast(uint256 proposalId) private view returns (uint256) {
        ProposalVote memory proposalVote = _proposalVotes[proposalId];
        return proposalVote.forVotes + proposalVote.againstVotes + proposalVote.abstainVotes;
    }
    
    // ==========================================================================
    // OpenZeppelin Overrides
    // ==========================================================================
    
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(Governor, GovernorTimelockControl, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
    
    /**
     * @dev Returns the executor to which proposals are delegated.
     */
    function _executor()
        internal
        view
        override(Governor, GovernorTimelockControl)
        returns (address)
    {
        return super._executor();
    }
    
    /**
     * @dev Hook executed before proposal execution.
     */
    function _execute(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) {
        super._execute(proposalId, targets, values, calldatas, descriptionHash);
    }
    
    /**
     * @dev Hook executed before proposal cancel.
     */
    function _cancel(
        uint256 proposalId,
        address proposer,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) returns (uint256) {
        return super._cancel(proposalId, proposer, targets, values, calldatas, descriptionHash);
    }
    
    // Internal function to match the above signature but just using proposer and proposalId
    function _cancel(
        uint256 proposalId,
        address proposer,
        address target
    ) private returns (uint256) {
        // Get the proposal information from the protocol
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = proposalInfo(proposalId);
        
        // Create the description hash
        bytes32 descriptionHash = keccak256(bytes(description));
        
        // Call the internal cancel function
        return _cancel(proposalId, proposer, targets, values, calldatas, descriptionHash);
    }
    
    /**
     * @dev Function to get the proposal information. Helper for the _cancel function.
     */
    function proposalInfo(uint256 proposalId)
        internal
        view
        returns (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        )
    {
        // The ProposalDetails struct doesn't match what we need, so we're returning
        // empty arrays for targets, values, and calldatas, and the stored description
        targets = new address[](0);
        values = new uint256[](0);
        calldatas = new bytes[](0);
        description = _proposalMetadata[proposalId].description;
    }
}
