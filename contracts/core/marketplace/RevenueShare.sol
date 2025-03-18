// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

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

interface IPrivaToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function getStakingTier(address account) external view returns (uint256 tierIndex, StakingTier memory tier);
    function getApplicableFeeRate(address account) external view returns (uint16);
    
    struct StakingTier {
        uint256 minAmount;
        uint16 rewardMultiplier;
        uint16 feeDiscount;
        bool marketplaceAccess;
        bool governanceAccess;
        bool priorityAccess;
    }
}

interface IDataMarketplace {
    function getListingForDataVault(uint256 dataVaultId) external view returns (uint256);
    function getListingTransactions(uint256 listingId) external view returns (Transaction[] memory);
    
    struct Transaction {
        uint256 listingId;
        uint256 dataVaultId;
        address seller;
        address buyer;
        uint256 price;
        uint8 accessType;
        uint256 timestamp;
        uint256 protocolFee;
        uint256 expiresAt;
    }
}

/**
 * @title PrivaSight Revenue Share
 * @dev Manages revenue distribution from data usage across data owners,
 * contributors, and stakeholders. Includes multiple distribution models,
 * batch processing, and automated payouts.
 */
contract RevenueShare is AccessControl, ReentrancyGuard, Pausable {
    using SafeMath for uint256;

    // ==========================================================================
    // Constants
    // ==========================================================================

    bytes32 public constant REVENUE_ADMIN_ROLE = keccak256("REVENUE_ADMIN_ROLE");
    bytes32 public constant DISTRIBUTOR_ROLE = keccak256("DISTRIBUTOR_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    // Revenue model types
    uint8 public constant MODEL_FIXED_PERCENTAGE = 1; // Fixed percentage for each stakeholder
    uint8 public constant MODEL_CONTRIBUTION_BASED = 2; // Based on data contribution
    uint8 public constant MODEL_STAKING_WEIGHTED = 3; // Weighted by staking amount
    uint8 public constant MODEL_HYBRID = 4; // Combination of the above

    // Stakeholder types
    uint8 public constant STAKEHOLDER_DATA_OWNER = 1; // Original data provider
    uint8 public constant STAKEHOLDER_CONTRIBUTOR = 2; // Contributing to data quality/verification
    uint8 public constant STAKEHOLDER_PLATFORM = 3; // Platform fee
    uint8 public constant STAKEHOLDER_STAKER = 4; // Token staker
    uint8 public constant STAKEHOLDER_COMMUNITY = 5; // Community fund

    // Payout status
    uint8 public constant PAYOUT_STATUS_PENDING = 1;
    uint8 public constant PAYOUT_STATUS_PROCESSING = 2;
    uint8 public constant PAYOUT_STATUS_COMPLETED = 3;
    uint8 public constant PAYOUT_STATUS_FAILED = 4;

    // Percentage base for calculations (10000 = 100%)
    uint16 public constant PERCENTAGE_BASE = 10000;

    // Minimum revenue distribution threshold (10 PRIVA tokens)
    uint256 public constant MIN_DISTRIBUTION_THRESHOLD = 10 * 10**18;

    // ==========================================================================
    // State Variables
    // ==========================================================================

    // External contract references
    IDataVaultNFT public dataVaultNFT;
    IPrivaToken public privaToken;
    IDataMarketplace public dataMarketplace;

    // Treasury and community fund addresses
    address public treasuryAddress;
    address public communityFundAddress;

    // Revenue model configuration
    struct RevenueModel {
        uint8 modelType;
        uint16 ownerPercentage; // Base percentage for data owner
        uint16 contributorPercentage; // Base percentage for contributors
        uint16 platformPercentage; // Platform fee percentage
        uint16 stakerPercentage; // Percentage for stakers
        uint16 communityPercentage; // Percentage for community fund
        bool active;
    }

    // Revenue distribution details per DataVault
    struct RevenueDistribution {
        uint256 dataVaultId;
        uint8 modelType;
        mapping(address => uint16) contributorShares; // Contributor shares in basis points
        address[] contributors; // List of contributors
        uint256 totalRevenue; // Accumulated revenue
        uint256 lastDistributionTime; // Last distribution timestamp
        bool autoDistribute; // Auto-distribution flag
    }

    // Payout record structure
    struct PayoutRecord {
        uint256 payoutId;
        uint256 dataVaultId;
        uint256 amount;
        address recipient;
        uint8 stakeholderType;
        uint8 status;
        uint256 timestamp;
        string description;
    }

    // Batch distribution job structure
    struct BatchDistributionJob {
        uint256 jobId;
        uint256[] dataVaultIds;
        uint256 startTime;
        uint256 endTime;
        uint8 status;
        uint256 totalDistributed;
        uint256 dataVaultsProcessed;
    }

    // Default revenue model
    RevenueModel public defaultModel;

    // Custom revenue models per DataVault
    mapping(uint256 => RevenueModel) public customModels;

    // Revenue distributions per DataVault
    mapping(uint256 => RevenueDistribution) private _revenueDistributions;

    // Payout records by payout ID
    mapping(uint256 => PayoutRecord) public payoutRecords;

    // Payout records by recipient
    mapping(address => uint256[]) private _recipientPayouts;

    // Payout records by DataVault
    mapping(uint256 => uint256[]) private _vaultPayouts;

    // Batch distribution jobs
    mapping(uint256 => BatchDistributionJob) public batchJobs;

    // Counters
    uint256 public payoutCounter;
    uint256 public batchJobCounter;

    // Platform statistics
    uint256 public totalRevenueDistributed;
    uint256 public totalDataOwnersRewarded;
    uint256 public totalPayoutsProcessed;

    // ==========================================================================
    // Events
    // ==========================================================================

    event RevenueModelSet(
        uint256 indexed dataVaultId,
        uint8 modelType,
        uint16 ownerPercentage,
        uint16 contributorPercentage,
        uint16 platformPercentage,
        uint16 stakerPercentage,
        uint16 communityPercentage
    );

    event ContributorAdded(uint256 indexed dataVaultId, address indexed contributor, uint16 sharePercentage);
    event ContributorRemoved(uint256 indexed dataVaultId, address indexed contributor);
    event RevenueReceived(uint256 indexed dataVaultId, uint256 amount, address indexed sender);
    event RevenueDistributed(
        uint256 indexed dataVaultId,
        uint256 totalAmount,
        uint256 ownerAmount,
        uint256 contributorsAmount,
        uint256 platformAmount,
        uint256 stakersAmount,
        uint256 communityAmount
    );
    event PayoutProcessed(
        uint256 indexed payoutId,
        uint256 indexed dataVaultId,
        address indexed recipient,
        uint256 amount,
        uint8 stakeholderType
    );
    event BatchDistributionStarted(uint256 indexed jobId, uint256 dataVaultCount, uint256 startTime);
    event BatchDistributionCompleted(uint256 indexed jobId, uint256 totalDistributed, uint256 dataVaultsProcessed, uint256 endTime);
    event TreasuryAddressUpdated(address oldAddress, address newAddress);
    event CommunityFundAddressUpdated(address oldAddress, address newAddress);

    // ==========================================================================
    // Constructor
    // ==========================================================================

    /**
     * @dev Initializes the RevenueShare contract with external contract references and initial settings.
     * @param _dataVaultNFT Address of the DataVault NFT contract
     * @param _privaToken Address of the PRIVA token contract
     * @param _dataMarketplace Address of the DataMarketplace contract
     * @param _treasuryAddress Address for platform fees
     * @param _communityFundAddress Address for community fund
     */
    constructor(
        address _dataVaultNFT,
        address _privaToken,
        address _dataMarketplace,
        address _treasuryAddress,
        address _communityFundAddress
    ) {
        require(_dataVaultNFT != address(0), "Invalid DataVault NFT address");
        require(_privaToken != address(0), "Invalid PRIVA token address");
        require(_dataMarketplace != address(0), "Invalid DataMarketplace address");
        require(_treasuryAddress != address(0), "Invalid treasury address");
        require(_communityFundAddress != address(0), "Invalid community fund address");

        dataVaultNFT = IDataVaultNFT(_dataVaultNFT);
        privaToken = IPrivaToken(_privaToken);
        dataMarketplace = IDataMarketplace(_dataMarketplace);
        treasuryAddress = _treasuryAddress;
        communityFundAddress = _communityFundAddress;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REVENUE_ADMIN_ROLE, msg.sender);
        _grantRole(DISTRIBUTOR_ROLE, msg.sender);
        _grantRole(TREASURY_ROLE, _treasuryAddress);

        // Initialize default revenue model (70% owner, 10% contributors, 10% platform, 5% stakers, 5% community)
        defaultModel = RevenueModel({
            modelType: MODEL_FIXED_PERCENTAGE,
            ownerPercentage: 7000,
            contributorPercentage: 1000,
            platformPercentage: 1000,
            stakerPercentage: 500,
            communityPercentage: 500,
            active: true
        });
    }

    // ==========================================================================
    // Revenue Model Management
    // ==========================================================================

    /**
     * @dev Sets the default revenue model for all DataVaults without custom models.
     * @param modelType Type of revenue model (1-4)
     * @param ownerPercentage Percentage for data owner
     * @param contributorPercentage Percentage for contributors
     * @param platformPercentage Percentage for platform
     * @param stakerPercentage Percentage for stakers
     * @param communityPercentage Percentage for community fund
     */
    function setDefaultRevenueModel(
        uint8 modelType,
        uint16 ownerPercentage,
        uint16 contributorPercentage,
        uint16 platformPercentage,
        uint16 stakerPercentage,
        uint16 communityPercentage
    ) external onlyRole(REVENUE_ADMIN_ROLE) {
        require(modelType >= MODEL_FIXED_PERCENTAGE && modelType <= MODEL_HYBRID, "Invalid model type");
        require(
            ownerPercentage + contributorPercentage + platformPercentage + stakerPercentage + communityPercentage == PERCENTAGE_BASE,
            "Percentages must sum to 100%"
        );

        defaultModel = RevenueModel({
            modelType: modelType,
            ownerPercentage: ownerPercentage,
            contributorPercentage: contributorPercentage,
            platformPercentage: platformPercentage,
            stakerPercentage: stakerPercentage,
            communityPercentage: communityPercentage,
            active: true
        });

        emit RevenueModelSet(0, modelType, ownerPercentage, contributorPercentage, platformPercentage, stakerPercentage, communityPercentage);
    }

    /**
     * @dev Sets a custom revenue model for a specific DataVault.
     * @param dataVaultId ID of the DataVault NFT
     * @param modelType Type of revenue model (1-4)
     * @param ownerPercentage Percentage for data owner
     * @param contributorPercentage Percentage for contributors
     * @param platformPercentage Percentage for platform
     * @param stakerPercentage Percentage for stakers
     * @param communityPercentage Percentage for community fund
     */
    function setCustomRevenueModel(
        uint256 dataVaultId,
        uint8 modelType,
        uint16 ownerPercentage,
        uint16 contributorPercentage,
        uint16 platformPercentage,
        uint16 stakerPercentage,
        uint16 communityPercentage
    ) external whenNotPaused nonReentrant {
        require(dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(REVENUE_ADMIN_ROLE, msg.sender), "Unauthorized");
        require(modelType >= MODEL_FIXED_PERCENTAGE && modelType <= MODEL_HYBRID, "Invalid model type");
        require(
            ownerPercentage + contributorPercentage + platformPercentage + stakerPercentage + communityPercentage == PERCENTAGE_BASE,
            "Percentages must sum to 100%"
        );

        customModels[dataVaultId] = RevenueModel({
            modelType: modelType,
            ownerPercentage: ownerPercentage,
            contributorPercentage: contributorPercentage,
            platformPercentage: platformPercentage,
            stakerPercentage: stakerPercentage,
            communityPercentage: communityPercentage,
            active: true
        });

        if (_revenueDistributions[dataVaultId].dataVaultId == 0) {
            _initializeRevenueDistribution(dataVaultId, modelType);
        } else {
            _revenueDistributions[dataVaultId].modelType = modelType;
        }

        emit RevenueModelSet(dataVaultId, modelType, ownerPercentage, contributorPercentage, platformPercentage, stakerPercentage, communityPercentage);
    }

    /**
     * @dev Initializes revenue distribution for a DataVault if not already set.
     * @param dataVaultId ID of the DataVault NFT
     * @param modelType Type of revenue model
     */
    function _initializeRevenueDistribution(uint256 dataVaultId, uint8 modelType) private {
        RevenueDistribution storage dist = _revenueDistributions[dataVaultId];
        dist.dataVaultId = dataVaultId;
        dist.modelType = modelType;
        dist.totalRevenue = 0;
        dist.lastDistributionTime = 0;
        dist.autoDistribute = true;
    }

    /**
     * @dev Retrieves the active revenue model for a DataVault.
     * @param dataVaultId ID of the DataVault NFT
     * @return modelType, ownerPercentage, contributorPercentage, platformPercentage, stakerPercentage, communityPercentage, active
     */
    function getRevenueModel(uint256 dataVaultId)
        external
        view
        returns (
            uint8 modelType,
            uint16 ownerPercentage,
            uint16 contributorPercentage,
            uint16 platformPercentage,
            uint16 stakerPercentage,
            uint16 communityPercentage,
            bool active
        )
    {
        RevenueModel storage custom = customModels[dataVaultId];
        if (custom.active) {
            return (
                custom.modelType,
                custom.ownerPercentage,
                custom.contributorPercentage,
                custom.platformPercentage,
                custom.stakerPercentage,
                custom.communityPercentage,
                custom.active
            );
        }
        return (
            defaultModel.modelType,
            defaultModel.ownerPercentage,
            defaultModel.contributorPercentage,
            defaultModel.platformPercentage,
            defaultModel.stakerPercentage,
            defaultModel.communityPercentage,
            defaultModel.active
        );
    }

    /**
     * @dev Sets the auto-distribution preference for a DataVault.
     * @param dataVaultId ID of the DataVault NFT
     * @param autoDistribute Enable/disable auto-distribution
     */
    function setAutoDistribute(uint256 dataVaultId, bool autoDistribute) external whenNotPaused {
        require(dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(REVENUE_ADMIN_ROLE, msg.sender), "Unauthorized");
        if (_revenueDistributions[dataVaultId].dataVaultId == 0) {
            _initializeRevenueDistribution(dataVaultId, defaultModel.modelType);
        }
        _revenueDistributions[dataVaultId].autoDistribute = autoDistribute;
    }

    // ==========================================================================
    // Contributor Management
    // ==========================================================================

    /**
     * @dev Adds a contributor to a DataVault’s revenue distribution.
     * @param dataVaultId ID of the DataVault NFT
     * @param contributor Address of the contributor
     * @param sharePercentage Contributor’s share in basis points
     */
    function addContributor(uint256 dataVaultId, address contributor, uint16 sharePercentage)
        external
        whenNotPaused
        nonReentrant
    {
        require(dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(REVENUE_ADMIN_ROLE, msg.sender), "Unauthorized");
        require(contributor != address(0), "Invalid contributor address");
        require(sharePercentage > 0 && sharePercentage <= PERCENTAGE_BASE, "Invalid share percentage");

        RevenueDistribution storage dist = _revenueDistributions[dataVaultId];
        if (dist.dataVaultId == 0) {
            _initializeRevenueDistribution(dataVaultId, defaultModel.modelType);
        }

        if (dist.contributorShares[contributor] == 0) {
            dist.contributors.push(contributor);
        }
        dist.contributorShares[contributor] = sharePercentage;

        emit ContributorAdded(dataVaultId, contributor, sharePercentage);
    }

    /**
     * @dev Removes a contributor from a DataVault’s revenue distribution.
     * @param dataVaultId ID of the DataVault NFT
     * @param contributor Address of the contributor
     */
    function removeContributor(uint256 dataVaultId, address contributor) external whenNotPaused nonReentrant {
        require(dataVaultNFT.ownerOf(dataVaultId) == msg.sender || hasRole(REVENUE_ADMIN_ROLE, msg.sender), "Unauthorized");
        RevenueDistribution storage dist = _revenueDistributions[dataVaultId];
        require(dist.contributorShares[contributor] > 0, "Contributor not found");

        dist.contributorShares[contributor] = 0;
        for (uint256 i = 0; i < dist.contributors.length; i++) {
            if (dist.contributors[i] == contributor) {
                dist.contributors[i] = dist.contributors[dist.contributors.length - 1];
                dist.contributors.pop();
                break;
            }
        }

        emit ContributorRemoved(dataVaultId, contributor);
    }

    /**
     * @dev Retrieves the list of contributors and their shares for a DataVault.
     * @param dataVaultId ID of the DataVault NFT
     * @return contributors Array of contributor addresses
     * @return shares Array of corresponding share percentages
     */
    function getContributors(uint256 dataVaultId)
        external
        view
        returns (address[] memory contributors, uint16[] memory shares)
    {
        RevenueDistribution storage dist = _revenueDistributions[dataVaultId];
        contributors = dist.contributors;
        shares = new uint16[](contributors.length);
        for (uint256 i = 0; i < contributors.length; i++) {
            shares[i] = dist.contributorShares[contributors[i]];
        }
    }

    // ==========================================================================
    // Revenue Reception and Distribution
    // ==========================================================================

    /**
     * @dev Receives revenue for a DataVault and triggers auto-distribution if applicable.
     * @param dataVaultId ID of the DataVault NFT
     * @param amount Amount of PRIVA tokens to receive
     */
    function receiveRevenue(uint256 dataVaultId, uint256 amount) external whenNotPaused nonReentrant {
        require(amount > 0, "Amount must be positive");
        require(privaToken.transfer(address(this), amount), "Token transfer failed");

        RevenueDistribution storage dist = _revenueDistributions[dataVaultId];
        if (dist.dataVaultId == 0) {
            _initializeRevenueDistribution(dataVaultId, defaultModel.modelType);
        }

        dist.totalRevenue = dist.totalRevenue.add(amount);
        emit RevenueReceived(dataVaultId, amount, msg.sender);

        if (dist.autoDistribute && dist.totalRevenue >= MIN_DISTRIBUTION_THRESHOLD) {
            distributeRevenue(dataVaultId);
        }
    }

    /**
     * @dev Collects pending revenue from the marketplace for a DataVault.
     * @param dataVaultId ID of the DataVault NFT
     * @return totalCollected Total revenue collected
     */
    function collectMarketplaceRevenue(uint256 dataVaultId)
        external
        whenNotPaused
        nonReentrant
        returns (uint256 totalCollected)
    {
        require(
            dataVaultNFT.ownerOf(dataVaultId) == msg.sender ||
                hasRole(DISTRIBUTOR_ROLE, msg.sender) ||
                hasRole(REVENUE_ADMIN_ROLE, msg.sender),
            "Unauthorized"
        );

        uint256 listingId = dataMarketplace.getListingForDataVault(dataVaultId);
        require(listingId > 0, "DataVault not listed");

        IDataMarketplace.Transaction[] memory transactions = dataMarketplace.getListingTransactions(listingId);
        RevenueDistribution storage dist = _revenueDistributions[dataVaultId];
        uint256 revenue = 0;

        for (uint256 i = 0; i < transactions.length; i++) {
            if (
                transactions[i].dataVaultId == dataVaultId &&
                transactions[i].timestamp > dist.lastDistributionTime
            ) {
                revenue = revenue.add(transactions[i].price.sub(transactions[i].protocolFee));
            }
        }

        if (revenue > 0) {
            receiveRevenue(dataVaultId, revenue);
            totalCollected = revenue;
        }
        return totalCollected;
    }

    /**
     * @dev Distributes accumulated revenue for a DataVault to all stakeholders.
     * @param dataVaultId ID of the DataVault NFT
     * @return totalDistributed Total amount distributed
     */
    function distributeRevenue(uint256 dataVaultId)
        public
        whenNotPaused
        nonReentrant
        returns (uint256 totalDistributed)
    {
        require(
            dataVaultNFT.ownerOf(dataVaultId) == msg.sender ||
                hasRole(DISTRIBUTOR_ROLE, msg.sender) ||
                hasRole(REVENUE_ADMIN_ROLE, msg.sender),
            "Unauthorized"
        );

        RevenueDistribution storage dist = _revenueDistributions[dataVaultId];
        uint256 revenue = dist.totalRevenue;
        require(revenue > 0, "No revenue to distribute");

        (
            uint8 modelType,
            uint16 ownerPercentage,
            uint16 contributorPercentage,
            uint16 platformPercentage,
            uint16 stakerPercentage,
            uint16 communityPercentage,
            bool active
        ) = getRevenueModel(dataVaultId);
        require(active, "Revenue model inactive");

        // Calculate distribution amounts
        uint256 ownerAmount = revenue.mul(ownerPercentage).div(PERCENTAGE_BASE);
        uint256 contributorsAmount = revenue.mul(contributorPercentage).div(PERCENTAGE_BASE);
        uint256 platformAmount = revenue.mul(platformPercentage).div(PERCENTAGE_BASE);
        uint256 stakersAmount = revenue.mul(stakerPercentage).div(PERCENTAGE_BASE);
        uint256 communityAmount = revenue.mul(communityPercentage).div(PERCENTAGE_BASE);

        // Reset revenue and update timestamp
        dist.totalRevenue = 0;
        dist.lastDistributionTime = block.timestamp;

        address dataOwner = dataVaultNFT.ownerOf(dataVaultId);

        // Process payouts
        if (ownerAmount > 0) {
            _processPayout(dataVaultId, dataOwner, ownerAmount, STAKEHOLDER_DATA_OWNER, "Data owner share");
        }

        if (contributorsAmount > 0) {
            if (dist.contributors.length > 0) {
                uint256 totalShares = 0;
                for (uint256 i = 0; i < dist.contributors.length; i++) {
                    totalShares = totalShares.add(dist.contributorShares[dist.contributors[i]]);
                }
                for (uint256 i = 0; i < dist.contributors.length; i++) {
                    address contributor = dist.contributors[i];
                    uint16 share = dist.contributorShares[contributor];
                    if (share > 0 && totalShares > 0) {
                        uint256 amount = contributorsAmount.mul(share).div(totalShares);
                        if (amount > 0) {
                            _processPayout(dataVaultId, contributor, amount, STAKEHOLDER_CONTRIBUTOR, "Contributor share");
                        }
                    }
                }
            } else {
                _processPayout(dataVaultId, dataOwner, contributorsAmount, STAKEHOLDER_DATA_OWNER, "Contributor share (to owner)");
            }
        }

        if (platformAmount > 0) {
            _processPayout(dataVaultId, treasuryAddress, platformAmount, STAKEHOLDER_PLATFORM, "Platform fee");
        }

        if (stakersAmount > 0) {
            _processPayout(dataVaultId, treasuryAddress, stakersAmount, STAKEHOLDER_STAKER, "Staker rewards (pending distribution)");
        }

        if (communityAmount > 0) {
            _processPayout(dataVaultId, communityFundAddress, communityAmount, STAKEHOLDER_COMMUNITY, "Community fund");
        }

        // Update statistics
        totalDistributed = revenue;
        totalRevenueDistributed = totalRevenueDistributed.add(totalDistributed);
        totalPayoutsProcessed = totalPayoutsProcessed.add(5); // Five stakeholder types

        bool ownerRewarded = false;
        for (uint256 i = 0; i < _vaultPayouts[dataVaultId].length; i++) {
            if (
                payoutRecords[_vaultPayouts[dataVaultId][i]].recipient == dataOwner &&
                payoutRecords[_vaultPayouts[dataVaultId][i]].stakeholderType == STAKEHOLDER_DATA_OWNER
            ) {
                ownerRewarded = true;
                break;
            }
        }
        if (!ownerRewarded) {
            totalDataOwnersRewarded = totalDataOwnersRewarded.add(1);
        }

        emit RevenueDistributed(dataVaultId, totalDistributed, ownerAmount, contributorsAmount, platformAmount, stakersAmount, communityAmount);
    }

    /**
     * @dev Processes a single payout to a recipient.
     * @param dataVaultId ID of the DataVault NFT
     * @param recipient Recipient address
     * @param amount Amount to pay
     * @param stakeholderType Type of stakeholder
     * @param description Payout description
     * @return payoutId Generated payout ID
     */
    function _processPayout(
        uint256 dataVaultId,
        address recipient,
        uint256 amount,
        uint8 stakeholderType,
        string memory description
    ) private returns (uint256 payoutId) {
        bool success = privaToken.transfer(recipient, amount);
        payoutCounter++;
        payoutId = payoutCounter;

        PayoutRecord memory payout = PayoutRecord({
            payoutId: payoutId,
            dataVaultId: dataVaultId,
            amount: amount,
            recipient: recipient,
            stakeholderType: stakeholderType,
            status: success ? PAYOUT_STATUS_COMPLETED : PAYOUT_STATUS_FAILED,
            timestamp: block.timestamp,
            description: description
        });

        payoutRecords[payoutId] = payout;
        _recipientPayouts[recipient].push(payoutId);
        _vaultPayouts[dataVaultId].push(payoutId);

        emit PayoutProcessed(payoutId, dataVaultId, recipient, amount, stakeholderType);
    }

    /**
     * @dev Retrieves revenue info for a DataVault.
     * @param dataVaultId ID of the DataVault NFT
     * @return totalRevenue Accumulated revenue
     * @return lastDistributionTime Last distribution timestamp
     */
    function getRevenueInfo(uint256 dataVaultId)
        external
        view
        returns (uint256 totalRevenue, uint256 lastDistributionTime)
    {
        RevenueDistribution storage dist = _revenueDistributions[dataVaultId];
        return (dist.totalRevenue, dist.lastDistributionTime);
    }

    /**
     * @dev Retrieves payout records for a recipient.
     * @param recipient Address of the recipient
     * @return Array of payout IDs
     */
    function getRecipientPayouts(address recipient) external view returns (uint256[] memory) {
        return _recipientPayouts[recipient];
    }

    /**
     * @dev Retrieves payout records for a DataVault.
     * @param dataVaultId ID of the DataVault NFT
     * @return Array of payout IDs
     */
    function getVaultPayouts(uint256 dataVaultId) external view returns (uint256[] memory) {
        return _vaultPayouts[dataVaultId];
    }

    // ==========================================================================
    // Batch Distribution
    // ==========================================================================

    /**
     * @dev Starts a batch distribution job for multiple DataVaults.
     * @param dataVaultIds Array of DataVault IDs
     * @return jobId Generated job ID
     */
    function startBatchDistribution(uint256[] memory dataVaultIds)
        external
        onlyRole(DISTRIBUTOR_ROLE)
        whenNotPaused
        returns (uint256 jobId)
    {
        require(dataVaultIds.length > 0, "No DataVaults specified");
        batchJobCounter++;
        jobId = batchJobCounter;

        BatchDistributionJob storage job = batchJobs[jobId];
        job.jobId = jobId;
        job.dataVaultIds = dataVaultIds;
        job.startTime = block.timestamp;
        job.status = PAYOUT_STATUS_PROCESSING;

        emit BatchDistributionStarted(jobId, dataVaultIds.length, block.timestamp);
        return jobId;
    }

    /**
     * @dev Processes a batch of DataVaults in a distribution job.
     * @param jobId ID of the batch job
     * @param batchSize Number of DataVaults to process
     * @return processedCount Number of DataVaults processed
     * @return distributedAmount Total amount distributed
     */
    function processBatchDistribution(uint256 jobId, uint256 batchSize)
        external
        onlyRole(DISTRIBUTOR_ROLE)
        whenNotPaused
        nonReentrant
        returns (uint256 processedCount, uint256 distributedAmount)
    {
        BatchDistributionJob storage job = batchJobs[jobId];
        require(job.jobId > 0, "Batch job not found");
        require(job.status == PAYOUT_STATUS_PROCESSING, "Batch job not processing");

        uint256 startIdx = job.dataVaultsProcessed;
        uint256 endIdx = startIdx.add(batchSize) > job.dataVaultIds.length ? job.dataVaultIds.length : startIdx.add(batchSize);

        uint256 totalDistributed = 0;
        uint256 processed = 0;

        for (uint256 i = startIdx; i < endIdx; i++) {
            uint256 dataVaultId = job.dataVaultIds[i];
            if (_revenueDistributions[dataVaultId].totalRevenue == 0) {
                processed++;
                continue;
            }
            try this.distributeRevenue(dataVaultId) returns (uint256 distributed) {
                totalDistributed = totalDistributed.add(distributed);
                processed++;
            } catch {
                processed++;
            }
        }

        job.dataVaultsProcessed = job.dataVaultsProcessed.add(processed);
        job.totalDistributed = job.totalDistributed.add(totalDistributed);

        if (job.dataVaultsProcessed >= job.dataVaultIds.length) {
            job.status = PAYOUT_STATUS_COMPLETED;
            job.endTime = block.timestamp;
            emit BatchDistributionCompleted(jobId, job.totalDistributed, job.dataVaultsProcessed, job.endTime);
        }

        return (processed, totalDistributed);
    }

    /**
     * @dev Retrieves the status of a batch distribution job.
     * @param jobId ID of the batch job
     * @return status, totalDistributed, dataVaultsProcessed, progress
     */
    function getBatchJobStatus(uint256 jobId)
        external
        view
        returns (
            uint8 status,
            uint256 totalDistributed,
            uint256 dataVaultsProcessed,
            uint256 progress
        )
    {
        BatchDistributionJob storage job = batchJobs[jobId];
        require(job.jobId > 0, "Batch job not found");
        uint256 progressPercent = job.dataVaultIds.length > 0 ? job.dataVaultsProcessed.mul(100).div(job.dataVaultIds.length) : 0;
        return (job.status, job.totalDistributed, job.dataVaultsProcessed, progressPercent);
    }

    // ==========================================================================
    // Address Management
    // ==========================================================================

    /**
     * @dev Updates the treasury address.
     * @param _treasuryAddress New treasury address
     */
    function setTreasuryAddress(address _treasuryAddress) external onlyRole(REVENUE_ADMIN_ROLE) {
        require(_treasuryAddress != address(0), "Invalid treasury address");
        address oldAddress = treasuryAddress;
        treasuryAddress = _treasuryAddress;
        _revokeRole(TREASURY_ROLE, oldAddress);
        _grantRole(TREASURY_ROLE, _treasuryAddress);
        emit TreasuryAddressUpdated(oldAddress, _treasuryAddress);
    }

    /**
     * @dev Updates the community fund address.
     * @param _communityFundAddress New community fund address
     */
    function setCommunityFundAddress(address _communityFundAddress) external onlyRole(REVENUE_ADMIN_ROLE) {
        require(_communityFundAddress != address(0), "Invalid community fund address");
        address oldAddress = communityFundAddress;
        communityFundAddress = _communityFundAddress;
        emit CommunityFundAddressUpdated(oldAddress, _communityFundAddress);
    }

    // ==========================================================================
    // Admin Functions
    // ==========================================================================

    /** @dev Pauses the contract, halting all operations except admin functions. */
    function pause() external onlyRole(REVENUE_ADMIN_ROLE) {
        _pause();
    }

    /** @dev Unpauses the contract, resuming normal operations. */
    function unpause() external onlyRole(REVENUE_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @dev Withdraws tokens accidentally sent to the contract (emergency use).
     * @param tokenAddress Address of the token to withdraw
     * @param amount Amount to withdraw
     */
    function emergencyWithdraw(address tokenAddress, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC20 token = IERC20(tokenAddress);
        if (tokenAddress == address(privaToken)) {
            uint256 balance = privaToken.balanceOf(address(this));
            require(balance >= amount, "Insufficient balance");
        }
        require(token.transfer(msg.sender, amount), "Transfer failed");
    }
}
