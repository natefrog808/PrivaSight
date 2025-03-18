// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title PrivaToken
 * @dev ERC20 token for the PrivaSight ecosystem with staking, governance, and
 * research participation rewards. Implements a deflationary mechanism and
 * tiered staking benefits.
 */
contract PrivaToken is 
    ERC20Burnable, 
    ERC20Pausable, 
    ERC20Permit, 
    ERC20Votes, 
    AccessControl 
{
    // ==========================================================================
    // Constants
    // ==========================================================================
    
    // Roles
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant REWARD_DISTRIBUTOR_ROLE = keccak256("REWARD_DISTRIBUTOR_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");
    
    // Token supply constants
    uint256 public constant MAX_SUPPLY = 1_000_000_000 * 10**18; // 1 billion tokens
    
    // Staking constants
    uint256 public constant MIN_STAKE_DURATION = 7 days;
    uint256 public constant MAX_STAKE_DURATION = 365 days;
    uint256 public constant MIN_STAKE_AMOUNT = 100 * 10**18; // 100 tokens
    
    // Base rates (basis points, 1% = 100)
    uint16 public constant BASE_REWARD_RATE = 500; // 5% annual base rate
    uint16 public constant UNSTAKE_PENALTY_RATE = 1000; // 10% penalty for early unstaking
    
    // Fee constants
    uint16 public constant MAX_FEE_RATE = 500; // 5% maximum fee
    
    // ==========================================================================
    // State Variables
    // ==========================================================================
    
    // Supply tracking
    uint256 private _circulatingSupply;
    
    // Staking tracking
    struct Stake {
        uint256 amount;
        uint256 startTime;
        uint256 endTime;
        bool active;
    }
    
    // Stake details by staker address and stake ID
    mapping(address => mapping(uint256 => Stake)) private _stakes;
    mapping(address => uint256) private _stakeCount;
    mapping(address => uint256) private _totalStakedAmount;
    
    // DataVault staking
    struct DataVaultStake {
        uint256 stakeId;
        uint256 dataVaultId;
        bool active;
    }
    
    // DataVault stakes by staker and vault ID
    mapping(address => mapping(uint256 => DataVaultStake)) private _dataVaultStakes;
    mapping(uint256 => address) private _dataVaultStaker;
    mapping(address => uint256) private _dataVaultCount;
    
    // Fees
    uint16 private _transactionFeeRate; // Basis points (e.g., the value 100 = 1%)
    address private _feeCollector;
    
    // Staking tiers - min amount => multiplier in basis points (100 = 1x, 150 = 1.5x)
    struct StakingTier {
        uint256 minAmount;
        uint16 rewardMultiplier;
        uint16 feeDiscount;
        bool marketplaceAccess;
        bool governanceAccess;
        bool priorityAccess;
    }
    
    StakingTier[] private _stakingTiers;
    
    // Rewards
    mapping(address => uint256) private _unclaimedRewards;
    
    // Events
    event Staked(address indexed staker, uint256 indexed stakeId, uint256 amount, uint256 duration);
    event Unstaked(address indexed staker, uint256 indexed stakeId, uint256 amount, bool penalized);
    event DataVaultStaked(address indexed staker, uint256 indexed dataVaultId, uint256 indexed stakeId);
    event DataVaultUnstaked(address indexed staker, uint256 indexed dataVaultId, uint256 indexed stakeId);
    event RewardDistributed(address indexed staker, uint256 amount, string reason);
    event RewardClaimed(address indexed staker, uint256 amount);
    event StakingTierAdded(uint256 tierIndex, uint256 minAmount, uint16 rewardMultiplier);
    event StakingTierUpdated(uint256 tierIndex, uint256 minAmount, uint16 rewardMultiplier);
    event FeeRateUpdated(uint16 oldRate, uint16 newRate);
    event FeeCollectorUpdated(address oldCollector, address newCollector);
    
    // ==========================================================================
    // Constructor
    // ==========================================================================
    
    /**
     * @dev Initializes the PrivaToken contract.
     * @param initialSupply The initial token supply to mint to the deployer.
     * @param feeCollector The address that will receive transaction fees.
     */
    constructor(uint256 initialSupply, address feeCollector) 
        ERC20("PrivaSight Token", "PRIVA") 
        ERC20Permit("PrivaSight Token")
    {
        require(initialSupply <= MAX_SUPPLY, "Initial supply exceeds maximum");
        require(feeCollector != address(0), "Fee collector cannot be zero address");
        
        _feeCollector = feeCollector;
        _transactionFeeRate = 100; // 1% default fee
        
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(REWARD_DISTRIBUTOR_ROLE, msg.sender);
        _grantRole(GOVERNANCE_ROLE, msg.sender);
        
        // Set up default staking tiers
        _setupStakingTiers();
        
        // Mint initial supply to deployer
        _mint(msg.sender, initialSupply);
        _circulatingSupply = initialSupply;
    }
    
    // ==========================================================================
    // Staking Functions
    // ==========================================================================
    
    /**
     * @dev Stake tokens for a specified duration to earn rewards.
     * @param amount The amount of tokens to stake
     * @param duration The duration in seconds for the stake
     * @return stakeId The unique identifier for the created stake
     */
    function stake(uint256 amount, uint256 duration) external whenNotPaused returns (uint256) {
        require(amount >= MIN_STAKE_AMOUNT, "Amount below minimum stake");
        require(duration >= MIN_STAKE_DURATION, "Duration below minimum");
        require(duration <= MAX_STAKE_DURATION, "Duration above maximum");
        require(balanceOf(msg.sender) >= amount, "Insufficient balance");
        
        // Transfer tokens to contract
        _transfer(msg.sender, address(this), amount);
        
        // Create new stake
        uint256 stakeId = _stakeCount[msg.sender];
        _stakeCount[msg.sender] += 1;
        
        _stakes[msg.sender][stakeId] = Stake({
            amount: amount,
            startTime: block.timestamp,
            endTime: block.timestamp + duration,
            active: true
        });
        
        _totalStakedAmount[msg.sender] += amount;
        
        emit Staked(msg.sender, stakeId, amount, duration);
        return stakeId;
    }
    
    /**
     * @dev Unstake tokens, applying a penalty if before the staking period ends.
     * @param stakeId The ID of the stake to unstake
     */
    function unstake(uint256 stakeId) external whenNotPaused {
        Stake storage userStake = _stakes[msg.sender][stakeId];
        
        require(userStake.active, "Stake not active");
        
        bool penalized = false;
        uint256 amountToReturn = userStake.amount;
        
        // Check if unstaking before lock period ends
        if (block.timestamp < userStake.endTime) {
            uint256 penalty = (userStake.amount * UNSTAKE_PENALTY_RATE) / 10000;
            amountToReturn = userStake.amount - penalty;
            penalized = true;
            
            // Burn the penalty amount
            _burn(address(this), penalty);
            _circulatingSupply -= penalty;
        }
        
        // Update staking state
        userStake.active = false;
        _totalStakedAmount[msg.sender] -= userStake.amount;
        
        // Return tokens to user
        _transfer(address(this), msg.sender, amountToReturn);
        
        emit Unstaked(msg.sender, stakeId, amountToReturn, penalized);
    }
    
    /**
     * @dev Stake tokens on a specific DataVault NFT to increase visibility and rewards.
     * @param dataVaultId The ID of the DataVault NFT
     * @param stakeId The ID of an existing stake to associate with the DataVault
     */
    function stakeOnDataVault(uint256 dataVaultId, uint256 stakeId) external whenNotPaused {
        Stake storage userStake = _stakes[msg.sender][stakeId];
        
        require(userStake.active, "Stake not active");
        require(_dataVaultStaker[dataVaultId] == address(0), "DataVault already has staker");
        
        // Associate the stake with the DataVault
        uint256 dvStakeId = _dataVaultCount[msg.sender];
        _dataVaultCount[msg.sender] += 1;
        
        _dataVaultStakes[msg.sender][dvStakeId] = DataVaultStake({
            stakeId: stakeId,
            dataVaultId: dataVaultId,
            active: true
        });
        
        _dataVaultStaker[dataVaultId] = msg.sender;
        
        emit DataVaultStaked(msg.sender, dataVaultId, stakeId);
    }
    
    /**
     * @dev Remove a stake from a DataVault NFT.
     * @param dvStakeId The ID of the DataVault stake to remove
     */
    function unstakeFromDataVault(uint256 dvStakeId) external whenNotPaused {
        DataVaultStake storage dvStake = _dataVaultStakes[msg.sender][dvStakeId];
        
        require(dvStake.active, "DataVault stake not active");
        
        // Remove the association
        dvStake.active = false;
        _dataVaultStaker[dvStake.dataVaultId] = address(0);
        
        emit DataVaultUnstaked(msg.sender, dvStake.dataVaultId, dvStake.stakeId);
    }
    
    /**
     * @dev Get details about a specific stake.
     * @param staker The address of the staker
     * @param stakeId The ID of the stake
     * @return amount The amount staked
     * @return startTime The start time of the stake
     * @return endTime The end time of the stake
     * @return active Whether the stake is active
     * @return reward The current reward amount for this stake
     */
    function getStakeDetails(address staker, uint256 stakeId) external view returns (
        uint256 amount,
        uint256 startTime,
        uint256 endTime,
        bool active,
        uint256 reward
    ) {
        Stake storage userStake = _stakes[staker][stakeId];
        
        return (
            userStake.amount,
            userStake.startTime,
            userStake.endTime,
            userStake.active,
            _calculateStakingReward(staker, stakeId)
        );
    }
    
    /**
     * @dev Get the staker of a specific DataVault NFT.
     * @param dataVaultId The ID of the DataVault NFT
     * @return The address of the staker, or zero address if none
     */
    function getDataVaultStaker(uint256 dataVaultId) external view returns (address) {
        return _dataVaultStaker[dataVaultId];
    }
    
    /**
     * @dev Get the staking tier of an address based on their total staked amount.
     * @param account The address to check
     * @return tierIndex The index of the staking tier
     * @return tier The staking tier details
     */
    function getStakingTier(address account) public view returns (
        uint256 tierIndex,
        StakingTier memory tier
    ) {
        uint256 totalStaked = _totalStakedAmount[account];
        
        // Start with the highest tier and work backwards
        for (uint256 i = _stakingTiers.length; i > 0; i--) {
            if (totalStaked >= _stakingTiers[i-1].minAmount) {
                return (i-1, _stakingTiers[i-1]);
            }
        }
        
        // Default to lowest tier
        return (0, _stakingTiers[0]);
    }
    
    /**
     * @dev Get all staking tiers.
     * @return The array of staking tiers
     */
    function getStakingTiers() external view returns (StakingTier[] memory) {
        return _stakingTiers;
    }
    
    // ==========================================================================
    // Reward Functions
    // ==========================================================================
    
    /**
     * @dev Distribute rewards to a staker for research participation or other contributions.
     * @param staker The address receiving the reward
     * @param amount The amount of tokens to reward
     * @param reason A string describing the reason for the reward
     */
    function distributeReward(address staker, uint256 amount, string memory reason) 
        external 
        onlyRole(REWARD_DISTRIBUTOR_ROLE) 
    {
        require(staker != address(0), "Staker cannot be zero address");
        require(amount > 0, "Reward amount must be positive");
        
        // Apply staking tier multiplier if applicable
        (, StakingTier memory tier) = getStakingTier(staker);
        
        if (tier.rewardMultiplier > 0) {
            amount = (amount * tier.rewardMultiplier) / 100;
        }
        
        // Ensure we don't exceed max supply
        uint256 mintAmount = amount;
        if (_circulatingSupply + mintAmount > MAX_SUPPLY) {
            mintAmount = MAX_SUPPLY - _circulatingSupply;
        }
        
        // Mint the reward tokens and update circulating supply
        _mint(address(this), mintAmount);
        _circulatingSupply += mintAmount;
        
        // Add to unclaimed rewards
        _unclaimedRewards[staker] += mintAmount;
        
        emit RewardDistributed(staker, mintAmount, reason);
    }
    
    /**
     * @dev Claim accumulated rewards.
     * @return The amount of rewards claimed
     */
    function claimRewards() external whenNotPaused returns (uint256) {
        uint256 rewards = _unclaimedRewards[msg.sender];
        require(rewards > 0, "No rewards to claim");
        
        _unclaimedRewards[msg.sender] = 0;
        _transfer(address(this), msg.sender, rewards);
        
        emit RewardClaimed(msg.sender, rewards);
        return rewards;
    }
    
    /**
     * @dev Get the unclaimed rewards for an address.
     * @param account The address to check
     * @return The amount of unclaimed rewards
     */
    function getUnclaimedRewards(address account) external view returns (uint256) {
        return _unclaimedRewards[account];
    }
    
    /**
     * @dev Calculate the staking reward for a specific stake.
     * @param staker The address of the staker
     * @param stakeId The ID of the stake
     * @return The current reward amount
     */
    function _calculateStakingReward(address staker, uint256 stakeId) private view returns (uint256) {
        Stake storage userStake = _stakes[staker][stakeId];
        
        if (!userStake.active) {
            return 0;
        }
        
        // Calculate time-based reward
        uint256 stakeDuration = Math.min(block.timestamp, userStake.endTime) - userStake.startTime;
        uint256 fullDuration = userStake.endTime - userStake.startTime;
        
        if (stakeDuration == 0 || fullDuration == 0) {
            return 0;
        }
        
        // Base reward calculation: amount * rate * (timePassed / 1 year)
        uint256 baseAnnualReward = (userStake.amount * BASE_REWARD_RATE) / 10000;
        uint256 timeRatio = (stakeDuration * 10000) / (365 days);
        uint256 reward = (baseAnnualReward * timeRatio) / 10000;
        
        // Apply staking tier multiplier
        (, StakingTier memory tier) = getStakingTier(staker);
        reward = (reward * tier.rewardMultiplier) / 100;
        
        return reward;
    }
    
    // ==========================================================================
    // Fee Functions
    // ==========================================================================
    
    /**
     * @dev Get the current transaction fee rate.
     * @return The fee rate in basis points (1% = 100)
     */
    function getTransactionFeeRate() external view returns (uint16) {
        return _transactionFeeRate;
    }
    
    /**
     * @dev Get the fee rate applicable for a specific account, considering staking tier discounts.
     * @param account The address to check
     * @return The fee rate in basis points (1% = 100)
     */
    function getApplicableFeeRate(address account) public view returns (uint16) {
        (, StakingTier memory tier) = getStakingTier(account);
        
        if (tier.feeDiscount >= _transactionFeeRate) {
            return 0;
        }
        
        return _transactionFeeRate - tier.feeDiscount;
    }
    
    /**
     * @dev Get the fee collector address.
     * @return The address that collects fees
     */
    function getFeeCollector() external view returns (address) {
        return _feeCollector;
    }
    
    /**
     * @dev Update the transaction fee rate.
     * @param newRate The new fee rate in basis points
     */
    function setTransactionFeeRate(uint16 newRate) external onlyRole(GOVERNANCE_ROLE) {
        require(newRate <= MAX_FEE_RATE, "Fee rate exceeds maximum");
        
        uint16 oldRate = _transactionFeeRate;
        _transactionFeeRate = newRate;
        
        emit FeeRateUpdated(oldRate, newRate);
    }
    
    /**
     * @dev Update the fee collector address.
     * @param newCollector The new fee collector address
     */
    function setFeeCollector(address newCollector) external onlyRole(GOVERNANCE_ROLE) {
        require(newCollector != address(0), "Fee collector cannot be zero address");
        
        address oldCollector = _feeCollector;
        _feeCollector = newCollector;
        
        emit FeeCollectorUpdated(oldCollector, newCollector);
    }
    
    // ==========================================================================
    // Staking Tier Management
    // ==========================================================================
    
    /**
     * @dev Add a new staking tier.
     * @param minAmount Minimum amount staked to qualify for this tier
     * @param rewardMultiplier Reward multiplier in basis points (100 = 1x)
     * @param feeDiscount Fee discount in basis points
     * @param marketplaceAccess Whether this tier grants marketplace access
     * @param governanceAccess Whether this tier grants governance access
     * @param priorityAccess Whether this tier grants priority access to features
     */
    function addStakingTier(
        uint256 minAmount,
        uint16 rewardMultiplier,
        uint16 feeDiscount,
        bool marketplaceAccess,
        bool governanceAccess,
        bool priorityAccess
    ) 
        external 
        onlyRole(GOVERNANCE_ROLE) 
    {
        require(minAmount > 0, "Minimum amount must be positive");
        require(rewardMultiplier >= 100, "Multiplier must be at least 100 (1x)");
        require(feeDiscount <= MAX_FEE_RATE, "Fee discount exceeds maximum fee");
        
        // Ensure tiers are added in ascending order of minAmount
        if (_stakingTiers.length > 0) {
            require(
                minAmount > _stakingTiers[_stakingTiers.length - 1].minAmount,
                "Tiers must be in ascending order"
            );
        }
        
        _stakingTiers.push(StakingTier({
            minAmount: minAmount,
            rewardMultiplier: rewardMultiplier,
            feeDiscount: feeDiscount,
            marketplaceAccess: marketplaceAccess,
            governanceAccess: governanceAccess,
            priorityAccess: priorityAccess
        }));
        
        emit StakingTierAdded(
            _stakingTiers.length - 1,
            minAmount,
            rewardMultiplier
        );
    }
    
    /**
     * @dev Update an existing staking tier.
     * @param tierIndex The index of the tier to update
     * @param minAmount New minimum amount staked
     * @param rewardMultiplier New reward multiplier
     * @param feeDiscount New fee discount
     * @param marketplaceAccess New marketplace access setting
     * @param governanceAccess New governance access setting
     * @param priorityAccess New priority access setting
     */
    function updateStakingTier(
        uint256 tierIndex,
        uint256 minAmount,
        uint16 rewardMultiplier,
        uint16 feeDiscount,
        bool marketplaceAccess,
        bool governanceAccess,
        bool priorityAccess
    ) 
        external 
        onlyRole(GOVERNANCE_ROLE) 
    {
        require(tierIndex < _stakingTiers.length, "Tier index out of bounds");
        require(minAmount > 0, "Minimum amount must be positive");
        require(rewardMultiplier >= 100, "Multiplier must be at least 100 (1x)");
        require(feeDiscount <= MAX_FEE_RATE, "Fee discount exceeds maximum fee");
        
        // Maintain ascending order of minAmount
        if (tierIndex > 0) {
            require(
                minAmount > _stakingTiers[tierIndex - 1].minAmount,
                "Must be greater than previous tier"
            );
        }
        
        if (tierIndex < _stakingTiers.length - 1) {
            require(
                minAmount < _stakingTiers[tierIndex + 1].minAmount,
                "Must be less than next tier"
            );
        }
        
        _stakingTiers[tierIndex] = StakingTier({
            minAmount: minAmount,
            rewardMultiplier: rewardMultiplier,
            feeDiscount: feeDiscount,
            marketplaceAccess: marketplaceAccess,
            governanceAccess: governanceAccess,
            priorityAccess: priorityAccess
        });
        
        emit StakingTierUpdated(
            tierIndex,
            minAmount,
            rewardMultiplier
        );
    }
    
    /**
     * @dev Initialize default staking tiers.
     */
    function _setupStakingTiers() private {
        // Tier 1: Basic (100 PRIVA)
        _stakingTiers.push(StakingTier({
            minAmount: 100 * 10**18,
            rewardMultiplier: 100, // 1x
            feeDiscount: 0,
            marketplaceAccess: false,
            governanceAccess: false,
            priorityAccess: false
        }));
        
        // Tier 2: Silver (1,000 PRIVA)
        _stakingTiers.push(StakingTier({
            minAmount: 1_000 * 10**18,
            rewardMultiplier: 125, // 1.25x
            feeDiscount: 25, // 0.25% discount
            marketplaceAccess: true,
            governanceAccess: false,
            priorityAccess: false
        }));
        
        // Tier 3: Gold (10,000 PRIVA)
        _stakingTiers.push(StakingTier({
            minAmount: 10_000 * 10**18,
            rewardMultiplier: 150, // 1.5x
            feeDiscount: 50, // 0.5% discount
            marketplaceAccess: true,
            governanceAccess: true,
            priorityAccess: false
        }));
        
        // Tier 4: Platinum (100,000 PRIVA)
        _stakingTiers.push(StakingTier({
            minAmount: 100_000 * 10**18,
            rewardMultiplier: 200, // 2x
            feeDiscount: 100, // 1% discount (full discount at default fee)
            marketplaceAccess: true,
            governanceAccess: true,
            priorityAccess: true
        }));
    }
    
    // ==========================================================================
    // Supply Management
    // ==========================================================================
    
    /**
     * @dev Get the maximum supply of tokens.
     * @return The maximum token supply
     */
    function getMaxSupply() external pure returns (uint256) {
        return MAX_SUPPLY;
    }
    
    /**
     * @dev Get the current circulating supply of tokens.
     * @return The circulating token supply
     */
    function getCirculatingSupply() external view returns (uint256) {
        return _circulatingSupply;
    }
    
    /**
     * @dev Internal function to check if a token transfer would exceed the maximum supply.
     * @param from The sender address
     * @param to The recipient address
     * @param amount The transfer amount
     */
    function _checkSupplyCap(address from, address to, uint256 amount) private view {
        // If minting new tokens (from == address(0))
        if (from == address(0)) {
            require(_circulatingSupply + amount <= MAX_SUPPLY, "Max supply exceeded");
        }
    }
    
    // ==========================================================================
    // Token Operations
    // ==========================================================================
    
    /**
     * @dev Override ERC20 transfer function to apply fees and check supply cap.
     * @param to The recipient address
     * @param amount The transfer amount
     * @return True if the transfer was successful
     */
    function transfer(address to, uint256 amount) public override returns (bool) {
        address sender = _msgSender();
        
        // Apply fee if applicable (but not for staking operations or reward claims)
        if (to != address(this) && _feeCollector != address(0)) {
            uint16 feeRate = getApplicableFeeRate(sender);
            
            if (feeRate > 0) {
                uint256 feeAmount = (amount * feeRate) / 10000;
                uint256 netAmount = amount - feeAmount;
                
                super.transfer(_feeCollector, feeAmount);
                return super.transfer(to, netAmount);
            }
        }
        
        return super.transfer(to, amount);
    }
    
    /**
     * @dev Override ERC20 transferFrom function to apply fees and check supply cap.
     * @param from The sender address
     * @param to The recipient address
     * @param amount The transfer amount
     * @return True if the transfer was successful
     */
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        // Apply fee if applicable (but not for staking operations or reward claims)
        if (to != address(this) && _feeCollector != address(0)) {
            uint16 feeRate = getApplicableFeeRate(from);
            
            if (feeRate > 0) {
                uint256 feeAmount = (amount * feeRate) / 10000;
                uint256 netAmount = amount - feeAmount;
                
                super.transferFrom(from, _feeCollector, feeAmount);
                return super.transferFrom(from, to, netAmount);
            }
        }
        
        return super.transferFrom(from, to, amount);
    }
    
    /**
     * @dev Mint new tokens, respecting the maximum supply.
     * @param to The recipient address
     * @param amount The amount to mint
     */
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        require(_circulatingSupply + amount <= MAX_SUPPLY, "Max supply exceeded");
        
        _mint(to, amount);
        _circulatingSupply += amount;
    }
    
    /**
     * @dev Pause token transfers and operations.
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }
    
    /**
     * @dev Unpause token transfers and operations.
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }
    
    // ==========================================================================
    // Override Required Functions
    // ==========================================================================
    
    /**
     * @dev Hook that is called before any transfer of tokens.
     * @param from The sender address
     * @param to The recipient address
     * @param amount The transfer amount
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override(ERC20, ERC20Pausable) {
        super._beforeTokenTransfer(from, to, amount);
        
        // Check supply cap on mint
        _checkSupplyCap(from, to, amount);
    }
    
    /**
     * @dev Hook that is called after any transfer of tokens.
     * @param from The sender address
     * @param to The recipient address
     * @param amount The transfer amount
     */
    function _afterTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override(ERC20, ERC20Votes) {
        super._afterTokenTransfer(from, to, amount);
        
        // Update circulating supply on burn
        if (to == address(0)) {
            _circulatingSupply -= amount;
        }
    }
    
    /**
     * @dev Hook that is called before token minting.
     * @param account The account receiving minted tokens
     * @param amount The amount being minted
     */
    function _mint(
        address account,
        uint256 amount
    ) internal override(ERC20, ERC20Votes) {
        super._mint(account, amount);
    }
    
    /**
     * @dev Hook that is called before token burning.
     * @param account The account whose tokens are being burned
     * @param amount The amount being burned
     */
    function _burn(
        address account,
        uint256 amount
    ) internal override(ERC20, ERC20Votes) {
        super._burn(account, amount);
    }
    
    // ==========================================================================
    // Governance Functions
    // ==========================================================================
    
    /**
     * @dev Check if an account has governance access based on their staking tier.
     * @param account The address to check
     * @return True if the account has governance access
     */
    function hasGovernanceAccess(address account) external view returns (bool) {
        if (hasRole(GOVERNANCE_ROLE, account)) {
            return true;
        }
        
        (, StakingTier memory tier) = getStakingTier(account);
        return tier.governanceAccess;
    }
    
    /**
     * @dev Check if an account has marketplace access based on their staking tier.
     * @param account The address to check
     * @return True if the account has marketplace access
     */
    function hasMarketplaceAccess(address account) external view returns (bool) {
        if (hasRole(GOVERNANCE_ROLE, account)) {
            return true;
        }
        
        (, StakingTier memory tier) = getStakingTier(account);
        return tier.marketplaceAccess;
    }
    
    /**
     * @dev Check if an account has priority access based on their staking tier.
     * @param account The address to check
     * @return True if the account has priority access
     */
    function hasPriorityAccess(address account) external view returns (bool) {
        if (hasRole(GOVERNANCE_ROLE, account)) {
            return true;
        }
        
        (, StakingTier memory tier) = getStakingTier(account);
        return tier.priorityAccess;
    }
}
