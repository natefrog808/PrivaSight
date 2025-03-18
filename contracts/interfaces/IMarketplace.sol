// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IMarketplace
 * @dev Interface for the PrivaSight Data Marketplace.
 * 
 * The PrivaSight Marketplace enables users to list, discover, and transact
 * DataVault NFTs with privacy controls, flexible pricing models, and transparent
 * revenue sharing. This interface defines the core functionality for these
 * marketplace interactions. Structs (Listing, ResearcherVerification, 
 * AccessRequest, Transaction) are defined externally.
 */
interface IMarketplace {
    // ==========================================================================
    // Constants
    // ==========================================================================

    /**
     * @dev Access types for DataVault listings.
     */
    function ACCESS_TYPE_ONE_TIME() external pure returns (uint8);    // One-time access
    function ACCESS_TYPE_SUBSCRIPTION() external pure returns (uint8); // Time-limited subscription access
    function ACCESS_TYPE_PERPETUAL() external pure returns (uint8);    // Perpetual access

    /**
     * @dev Payment model types for DataVault listings.
     */
    function PAYMENT_MODEL_FIXED() external pure returns (uint8);        // Fixed price model
    function PAYMENT_MODEL_PER_QUERY() external pure returns (uint8);    // Pay per query/access
    function PAYMENT_MODEL_REVENUE_SHARE() external pure returns (uint8); // Share of resulting revenue

    /**
     * @dev Listing states.
     */
    function LISTING_STATE_ACTIVE() external pure returns (uint8);   // Listing is active
    function LISTING_STATE_PAUSED() external pure returns (uint8);   // Listing is paused
    function LISTING_STATE_CLOSED() external pure returns (uint8);   // Listing is closed

    // ==========================================================================
    // Events
    // ==========================================================================

    /** @dev Emitted when a new DataVault listing is created. */
    event ListingCreated(
        uint256 indexed listingId,
        uint256 indexed dataVaultId,
        address indexed owner,
        uint256 price,
        uint8 accessType
    );

    /** @dev Emitted when a listing is updated. */
    event ListingUpdated(
        uint256 indexed listingId,
        uint256 price,
        uint8 state
    );

    /** @dev Emitted when a listing is closed. */
    event ListingClosed(
        uint256 indexed listingId,
        uint256 indexed dataVaultId,
        address indexed owner
    );

    /** @dev Emitted when access to a DataVault is requested. */
    event AccessRequested(
        uint256 indexed listingId,
        address indexed researcher,
        string purpose,
        uint256 offeredPrice
    );

    /** @dev Emitted when access to a DataVault is approved. */
    event AccessApproved(
        uint256 indexed listingId,
        address indexed researcher,
        uint256 expiresAt
    );

    /** @dev Emitted when access to a DataVault is denied. */
    event AccessDenied(
        uint256 indexed listingId,
        address indexed researcher,
        string reason
    );

    /** @dev Emitted when a marketplace transaction is executed. */
    event TransactionExecuted(
        uint256 indexed listingId,
        uint256 indexed dataVaultId,
        address indexed buyer,
        address seller,
        uint256 price,
        uint8 accessType
    );

    /** @dev Emitted when a researcher is verified. */
    event ResearcherVerified(
        address indexed researcher,
        address indexed verifier,
        string organization
    );

    /** @dev Emitted when a new category is added to the marketplace. */
    event CategoryAdded(
        string category
    );

    /** @dev Emitted when the protocol fee is updated. */
    event ProtocolFeeUpdated(
        uint16 oldFee,
        uint16 newFee
    );

    /** @dev Emitted when the fee collector address is updated. */
    event FeeCollectorUpdated(
        address oldCollector,
        address newCollector
    );

    /** @dev Emitted when the marketplace is paused. */
    event Paused(address account);

    /** @dev Emitted when the marketplace is unpaused. */
    event Unpaused(address account);

    // ==========================================================================
    // Listing Management Functions
    // ==========================================================================

    /**
     * @dev Create a new listing for a DataVault NFT.
     * @return listingId ID of the created listing
     */
    function createListing(
        uint256 dataVaultId,
        uint256 price,
        uint8 accessType,
        uint8 paymentModel,
        uint256 subscriptionPeriod,
        string calldata accessRequirements,
        string calldata dataDescription,
        string[] calldata dataTags,
        bool verificationRequired,
        uint256 revenueSharePercentage,
        string calldata category
    ) external returns (uint256 listingId);

    /** @dev Update an existing listing. */
    function updateListing(
        uint256 listingId,
        uint256 price,
        uint8 state,
        bool verificationRequired,
        string calldata accessRequirements,
        string calldata dataDescription,
        string[] calldata dataTags
    ) external;

    /** @dev Close a listing, removing it from the marketplace. */
    function closeListing(
        uint256 listingId
    ) external;

    /** @dev Get all listings for a specific owner. */
    function getListingsByOwner(
        address owner
    ) external view returns (uint256[] memory listingIds);

    /** @dev Get all listings in a specific category. */
    function getListingsByCategory(
        string calldata category
    ) external view returns (uint256[] memory listingIds);

    /** @dev Get listing ID for a DataVault NFT. */
    function getListingForDataVault(
        uint256 dataVaultId
    ) external view returns (uint256);

    /** @dev Get all available categories. */
    function getAllCategories() external view returns (string[] memory);

    // ==========================================================================
    // Access Request and Approval Functions
    // ==========================================================================

    /**
     * @dev Request access to a listed DataVault.
     * @return requestId Index of the created request
     */
    function requestAccess(
        uint256 listingId,
        string calldata purpose,
        uint256 offeredPrice
    ) external returns (uint256 requestId);

    /** @dev Approve an access request. */
    function approveAccess(
        uint256 listingId,
        uint256 requestId,
        uint256 agreedPrice
    ) external;

    /** @dev Deny an access request. */
    function denyAccess(
        uint256 listingId,
        uint256 requestId,
        string calldata reason
    ) external;

    /** @dev Check if a researcher has active access to a DataVault. */
    function hasActiveAccess(
        address researcher,
        uint256 dataVaultId
    ) external view returns (bool);

    /** @dev Get access expiration time for a researcher and DataVault. */
    function getAccessExpiration(
        address researcher,
        uint256 dataVaultId
    ) external view returns (uint256);

    /** @dev Get all access requests for a listing. */
    function getAccessRequests(
        uint256 listingId
    ) external view returns (AccessRequest[] memory);

    /** @dev Get all access requests made by a researcher. */
    function getRequestsByResearcher(
        address researcher
    ) external view returns (uint256[] memory);

    // ==========================================================================
    // Transaction Functions
    // ==========================================================================

    /**
     * @dev Direct purchase for fixed-price listings (no approval needed).
     * @return Transaction successful
     */
    function directPurchase(
        uint256 listingId
    ) external returns (bool);

    /**
     * @dev Record a query execution for per-query payment model.
     * @return Query recorded successfully
     */
    function recordQuery(
        uint256 listingId,
        address researcher
    ) external returns (bool);

    /** @dev Get transactions for a listing. */
    function getListingTransactions(
        uint256 listingId
    ) external view returns (Transaction[] memory);

    /** @dev Get transactions for a user (buyer). */
    function getUserTransactions(
        address user
    ) external view returns (Transaction[] memory);

    // ==========================================================================
    // Researcher Verification Functions
    // ==========================================================================

    /**
     * @dev Submit researcher credentials for verification.
     * @return Submission successful
     */
    function submitResearcherCredentials(
        string calldata organization,
        string calldata credentials
    ) external returns (bool);

    /**
     * @dev Verify a researcher's credentials.
     * @return Verification successful
     */
    function verifyResearcher(
        address researcher
    ) external returns (bool);

    /**
     * @dev Revoke a researcher's verification.
     * @return Revocation successful
     */
    function revokeVerification(
        address researcher
    ) external returns (bool);

    /** @dev Check if a researcher is verified. */
    function isResearcherVerified(
        address researcher
    ) external view returns (bool);

    /** @dev Get verification history for a researcher. */
    function getVerificationHistory(
        address researcher
    ) external view returns (address[] memory);

    // ==========================================================================
    // Category and Discovery Functions
    // ==========================================================================

    /**
     * @dev Add a new category to the marketplace.
     * @return Addition successful
     */
    function addCategory(
        string calldata category
    ) external returns (bool);

    /** @dev Search for listings based on criteria. */
    function searchListings(
        string calldata category,
        uint256 minPrice,
        uint256 maxPrice,
        uint8 accessType,
        string[] calldata tags,
        bool requireVerification
    ) external view returns (uint256[] memory);

    /** @dev Get featured listings (based on criteria like popularity, quality). */
    function getFeaturedListings(
        uint256 count
    ) external view returns (uint256[] memory);

    /** @dev Get recommended listings for a researcher based on history. */
    function getRecommendedListings(
        address researcher,
        uint256 count
    ) external view returns (uint256[] memory);

    // ==========================================================================
    // Fee Management Functions
    // ==========================================================================

    /** @dev Get the current protocol fee rate (in basis points, 1% = 100). */
    function getProtocolFeeRate() external view returns (uint16);

    /** @dev Update the protocol fee rate. */
    function setProtocolFeeRate(
        uint16 newFeeRate
    ) external;

    /** @dev Get the fee collector address. */
    function getFeeCollector() external view returns (address);

    /** @dev Update the fee collector address. */
    function setFeeCollector(
        address newFeeCollector
    ) external;

    // ==========================================================================
    // Statistics Functions
    // ==========================================================================

    /** @dev Get marketplace statistics. */
    function getMarketplaceStats() external view returns (
        uint256 totalListings,
        uint256 activeListings,
        uint256 totalTransactions,
        uint256 totalVolume,
        uint256 uniqueBuyers,
        uint256 uniqueSellers
    );

    /** @dev Get statistics for a specific category. */
    function getCategoryStats(
        string calldata category
    ) external view returns (
        uint256 listingCount,
        uint256 transactionCount,
        uint256 volume,
        uint256 averagePrice
    );

    // ==========================================================================
    // Admin Functions
    // ==========================================================================

    /** @dev Pause the marketplace. */
    function pause() external;

    /** @dev Unpause the marketplace. */
    function unpause() external;

    /** @dev Check if the marketplace is paused. */
    function isPaused() external view returns (bool);
}
