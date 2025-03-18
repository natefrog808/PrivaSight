// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";

/**
 * @title IDataVaultNFT
 * @dev Interface for the PrivaSight DataVault NFT contract.
 * 
 * DataVault NFTs represent encrypted personal data stored on-chain with
 * granular privacy controls, stakeable assets, and revenue-generating potential.
 * This interface defines the core functionality for minting, managing, and
 * monetizing personal data while maintaining privacy and ownership.
 * Structs (DataVault, AccessRequest, UsageStatistics) are defined externally.
 */
interface IDataVaultNFT is IERC721, IERC721Metadata {
    // ==========================================================================
    // Events
    // ==========================================================================

    event DataVaultMinted(
        uint256 indexed tokenId,
        address indexed owner,
        string dataHash,
        string dataCategory
    );

    event AccessRulesUpdated(
        uint256 indexed tokenId,
        string accessRules
    );

    event DataHashUpdated(
        uint256 indexed tokenId,
        string newDataHash
    );

    event StakeAdded(
        uint256 indexed tokenId,
        address indexed staker,
        uint256 amount
    );

    event AccessRequested(
        uint256 indexed tokenId,
        address indexed requester,
        string purpose
    );

    event AccessGranted(
        uint256 indexed tokenId,
        address indexed requester,
        uint256 expiresAt
    );

    event AccessRevoked(
        uint256 indexed tokenId,
        address indexed requester
    );

    event ResultsPublished(
        uint256 indexed tokenId,
        address indexed researcher,
        string resultHash
    );

    event RevenueDistributed(
        uint256 indexed tokenId,
        address indexed owner,
        uint256 amount
    );

    event StakingRewardsWithdrawn(
        uint256 indexed tokenId,
        address indexed owner,
        uint256 amount
    );

    // ==========================================================================
    // Core DataVault Functions
    // ==========================================================================

    function mintDataVault(
        string calldata dataHash,
        string calldata encryptionKeyHash,
        string calldata accessRules,
        string calldata dataCategory,
        string calldata metadataURI,
        uint256 stakingAmount
    ) external returns (uint256 tokenId);

    function updateAccessRules(
        uint256 tokenId,
        string calldata newRules
    ) external;

    function updateDataHash(
        uint256 tokenId,
        string calldata newDataHash,
        string calldata newEncryptionKeyHash
    ) external;

    function addStake(
        uint256 tokenId,
        uint256 amount
    ) external;

    function getDataVaultInfo(uint256 tokenId) external view returns (
        string memory dataHash,
        string memory accessRules,
        string memory dataCategory,
        uint256 stakingAmount,
        uint256 lastUpdated
    );

    // ==========================================================================
    // Access Control Functions
    // ==========================================================================

    function requestAccess(
        uint256 tokenId,
        string calldata purpose,
        uint256 compensation
    ) external returns (uint256 requestId);

    function approveAccess(
        uint256 tokenId,
        uint256 requestId,
        uint256 durationSeconds
    ) external;

    function revokeAccess(
        uint256 tokenId,
        address researcher
    ) external;

    function hasAccess(
        uint256 tokenId,
        address researcher
    ) external view returns (bool);

    function getAccessExpiration(
        uint256 tokenId,
        address researcher
    ) external view returns (uint256);

    function getAccessRequests(
        uint256 tokenId
    ) external view returns (AccessRequest[] memory);

    // ==========================================================================
    // Research and Computation Functions
    // ==========================================================================

    function publishResults(
        uint256 tokenId,
        uint256 requestId,
        string calldata resultHash
    ) external;

    function getUsageStatistics(uint256 tokenId) external view returns (
        uint256 timesAccessed,
        uint256 tokensEarned
    );

    function recordUsage(
        uint256 tokenId,
        address researcher,
        string calldata usageType
    ) external returns (bool);

    // ==========================================================================
    // Revenue and Token Functions
    // ==========================================================================

    function getStakedBalance(
        uint256 tokenId
    ) external view returns (uint256);

    function withdrawStakingRewards(
        uint256 tokenId
    ) external returns (uint256 amount);

    function getStaker(
        uint256 tokenId
    ) external view returns (address);

    function calculateRevenueShares(
        uint256 tokenId,
        uint256 totalAmount
    ) external view returns (
        uint256 ownerShare,
        uint256 stakerShare,
        uint256 platformShare
    );

    // ==========================================================================
    // Compliance and Management Functions
    // ==========================================================================

    function isVerified(
        uint256 tokenId
    ) external view returns (bool);

    function getVerificationDetails(
        uint256 tokenId
    ) external view returns (
        bool verified,
        uint256 verificationDate,
        address verifier
    );

    function verifyDataVault(
        uint256 tokenId
    ) external returns (bool);

    function getDataVaultsByOwner(
        address owner
    ) external view returns (uint256[] memory);

    function getDataVaultsByCategory(
        string calldata category
    ) external view returns (uint256[] memory);

    function totalSupply() external view returns (uint256);
}
