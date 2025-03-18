// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import "@openzeppelin/contracts/interfaces/IERC5267.sol";

/**
 * @title IPrivaToken
 * @dev Interface for the PrivaSight governance and utility token (PRIVA).
 * 
 * The PRIVA token serves as the economic backbone of the PrivaSight ecosystem,
 * enabling staking, governance, fee reduction, and reward distribution for data
 * providers. This interface defines the core functionality for the token, including
 * staking mechanisms, tiered benefits, and governance capabilities.
 * Structs (Stake, DataVaultStake, StakingTier) are defined externally.
 */
interface IPrivaToken is IERC20, IERC20Metadata, IERC20Permit, IERC5267 {
    // ==========================================================================
    // Events
    // ==========================================================================

    /**
     * @dev Emitted when a user stakes tokens.
     * @param staker Address of the staker
     * @param stakeId Unique ID of the stake
     * @param amount Amount of tokens staked
     * @param duration Duration of the stake in seconds
     */
    event Staked(
        address indexed staker,
        uint256 indexed stakeId,
        uint256 amount,
        uint256 duration
    );

    /**
     * @dev Emitted when a user unstakes tokens.
     * @param staker Address of the staker
     * @param stakeId ID of the stake
     * @param amount Amount of tokens returned
     * @param penalized Whether a penalty was applied for early unstaking
     */
    event Unstaked(
        address indexed staker,
        uint256 indexed stakeId,
        uint256 amount,
        bool penalized
    );

    /**
     * @dev Emitted when a user stakes tokens on a DataVault.
     * @param staker Address of the staker
     * @param dataVaultId ID of the DataVault
     * @param stakeId ID of the stake used
     */
    event DataVaultStaked(
        address indexed staker,
        uint256 indexed dataVaultId,
        uint256 indexed stakeId
    );

    /**
     * @dev Emitted when a user unstakes tokens from a DataVault.
     * @param staker Address of the staker
     * @param dataVaultId ID of the DataVault
     * @param stakeId ID of the stake
     */
    event DataVaultUnstaked(
        address indexed staker,
        uint256 indexed dataVaultId,
        uint256 indexed stakeId
    );

    /**
     * @dev Emitted when rewards are distributed to a staker.
     * @param staker Address receiving the reward
     * @param amount Amount of tokens rewarded
     * @param reason Reason for the reward distribution
     */
    event RewardDistributed(
        address indexed staker,
        uint256 amount,
        string reason
    );

    /**
     * @dev Emitted when a user claims accumulated rewards.
     * @param staker Address claiming the rewards
     * @param amount Amount of tokens claimed
     */
    event RewardClaimed(
        address indexed staker,
        uint256 amount
    );

    /**
     * @dev Emitted when a new staking tier is added.
     * @param tierIndex Index of the new tier
     * @param minAmount Minimum amount required for this tier
     * @param rewardMultiplier Reward multiplier for this tier
     */
    event StakingTierAdded(
        uint256 tierIndex,
        uint256 minAmount,
        uint16 rewardMultiplier
    );

    /**
     * @dev Emitted when a staking tier is updated.
     * @param tierIndex Index of the tier
     * @param minAmount New minimum amount
     * @param rewardMultiplier New reward multiplier
     */
    event StakingTierUpdated(
        uint256 tierIndex,
        uint256 minAmount,
        uint16 rewardMultiplier
    );

    /**
     * @dev Emitted when the transaction fee rate is updated.
     * @param oldRate Previous fee rate (in basis points)
     * @param newRate New fee rate (in basis points)
     */
    event FeeRateUpdated(
        uint16 oldRate,
        uint16 newRate
    );

    /**
     * @dev Emitted when the fee collector address is updated.
     * @param oldCollector Previous collector address
     * @param newCollector New collector address
     */
    event FeeCollectorUpdated(
        address oldCollector,
        address newCollector
    );

    /**
     * @dev Emitted when the token is paused.
     * @param account Address that triggered the pause
     */
    event Paused(address account);

    /**
     * @dev Emitted when the token is unpaused.
     * @param account Address that triggered the unpause
     */
    event Unpaused(address account);

    // ==========================================================================
    // Staking Functions
    // ==========================================================================

    /**
     * @dev Stake tokens for a specified duration to earn rewards.
     * @param amount Amount of tokens to stake
     * @param duration Duration in seconds for the stake
     * @return stakeId Unique identifier for the created stake
     */
    function stake(
        uint256 amount,
        uint256 duration
    ) external returns (uint256 stakeId);

    /**
     * @dev Unstake tokens after the staking period has completed.
     * @param stakeId ID of the stake to unstake
     */
    function unstake(
        uint256 stakeId
    ) external;

    /**
     * @dev Stake tokens on a specific DataVault NFT to increase visibility and rewards.
     * @param dataVaultId ID of the DataVault NFT
     * @param stakeId ID of an existing stake to associate with the DataVault
     */
    function stakeOnDataVault(
        uint256 dataVaultId,
        uint256 stakeId
    ) external;

    /**
     * @dev Remove a stake from a DataVault NFT.
     * @param dvStakeId ID of the DataVault stake to remove
     */
    function unstakeFromDataVault(
        uint256 dvStakeId
    ) external;

    /**
     * @dev Get details about a specific stake.
     * @param staker Address of the staker
     * @param stakeId ID of the stake
     * @return amount Amount staked
     * @return startTime Start time of the stake
     * @return endTime End time of the stake
     * @return active Whether the stake is active
     * @return reward Current reward amount for this stake
     */
    function getStakeDetails(
        address staker,
        uint256 stakeId
    ) external view returns (
        uint256 amount,
        uint256 startTime,
        uint256 endTime,
        bool active,
        uint256 reward
    );

    /**
     * @dev Get the staker of a specific DataVault NFT.
     * @param dataVaultId ID of the DataVault NFT
     * @return Address of the staker, or zero address if none
     */
    function getDataVaultStaker(
        uint256 dataVaultId
    ) external view returns (address);

    /**
     * @dev Get the staking tier of an address based on their total staked amount.
     * @param account Address to check
     * @return tierIndex Index of the staking tier
     * @return tier Staking tier details
     */
    function getStakingTier(
        address account
    ) external view returns (
        uint256 tierIndex,
        StakingTier memory tier
    );

    /**
     * @dev Get all staking tiers.
     * @return Array of staking tiers
     */
    function getStakingTiers() external view returns (StakingTier[] memory);

    // ==========================================================================
    // Reward Functions
    // ==========================================================================

    /**
     * @dev Distribute rewards to a staker for research participation or other contributions.
     * @param staker Address receiving the reward
     * @param amount Amount of tokens to reward
     * @param reason Description of the reason for the reward
     */
    function distributeReward(
        address staker,
        uint256 amount,
        string calldata reason
    ) external;

    /**
     * @dev Claim accumulated rewards.
     * @return Amount of rewards claimed
     */
    function claimRewards() external returns (uint256);

    /**
     * @dev Get the unclaimed rewards for an address.
     * @param account Address to check
     * @return Amount of unclaimed rewards
     */
    function getUnclaimedRewards(
        address account
    ) external view returns (uint256);

    // ==========================================================================
    // Fee Functions
    // ==========================================================================

    /**
     * @dev Get the current transaction fee rate.
     * @return Fee rate in basis points (1% = 100)
     */
    function getTransactionFeeRate() external view returns (uint16);

    /**
     * @dev Get the fee rate applicable for a specific account, considering staking tier discounts.
     * @param account Address to check
     * @return Fee rate in basis points (1% = 100)
     */
    function getApplicableFeeRate(
        address account
    ) external view returns (uint16);

    /**
     * @dev Get the fee collector address.
     * @return Address that collects fees
     */
    function getFeeCollector() external view returns (address);

    /**
     * @dev Update the transaction fee rate.
     * @param newRate New fee rate in basis points
     */
    function setTransactionFeeRate(
        uint16 newRate
    ) external;

    /**
     * @dev Update the fee collector address.
     * @param newCollector New fee collector address
     */
    function setFeeCollector(
        address newCollector
    ) external;

    // ==========================================================================
    // Supply Management
    // ==========================================================================

    /**
     * @dev Get the maximum supply of tokens.
     * @return Maximum token supply
     */
    function getMaxSupply() external pure returns (uint256);

    /**
     * @dev Get the current circulating supply of tokens.
     * @return Circulating token supply
     */
    function getCirculatingSupply() external view returns (uint256);

    /**
     * @dev Mint new tokens, respecting the maximum supply.
     * @param to Recipient address
     * @param amount Amount to mint
     */
    function mint(
        address to,
        uint256 amount
    ) external;

    /**
     * @dev Pause token transfers and operations.
     */
    function pause() external;

    /**
     * @dev Unpause token transfers and operations.
     */
    function unpause() external;

    // ==========================================================================
    // Governance Functions
    // ==========================================================================

    /**
     * @dev Check if an account has governance access based on their staking tier.
     * @param account Address to check
     * @return Whether the account has governance access
     */
    function hasGovernanceAccess(
        address account
    ) external view returns (bool);

    /**
     * @dev Check if an account has marketplace access based on their staking tier.
     * @param account Address to check
     * @return Whether the account has marketplace access
     */
    function hasMarketplaceAccess(
        address account
    ) external view returns (bool);

    /**
     * @dev Check if an account has priority access based on their staking tier.
     * @param account Address to check
     * @return Whether the account has priority access
     */
    function hasPriorityAccess(
        address account
    ) external view returns (bool);
}
