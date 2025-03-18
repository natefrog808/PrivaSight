// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

interface IDataVaultNFT {
    function getDataVaultInfo(uint256 tokenId) external view returns (
        string memory dataHash,
        string memory accessRules,
        string memory dataCategory,
        uint256 stakingAmount,
        uint256 lastUpdated
    );
    
    function ownerOf(uint256 tokenId) external view returns (address);
    function hasAccess(uint256 tokenId, address researcher) external view returns (bool);
    function getUsageStatistics(uint256 tokenId) external view returns (
        uint256 timesAccessed,
        uint256 tokensEarned
    );
}

interface IPrivaToken {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function hasMarketplaceAccess(address account) external view returns (bool);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function getApplicableFeeRate(address account) external view returns (uint16);
}

/**
 * @title PrivaSight Data Marketplace
 * @dev Marketplace for listing, discovering, and transacting DataVault NFTs
 * with built-in privacy controls, revenue sharing, and category-based discovery.
 */
contract DataMarketplace is AccessControl, ReentrancyGuard, Pausable {
    using SafeMath for uint256;

    // ==========================================================================
    // Constants
    // ==========================================================================

    bytes32 public constant MARKETPLACE_ADMIN_ROLE = keccak256("MARKETPLACE_ADMIN_ROLE");
    bytes32 public constant FEE_MANAGER_ROLE = keccak256("FEE_MANAGER_ROLE");
    bytes32 public constant VERIFICATION_ROLE = keccak256("VERIFICATION_ROLE");

    // **Access Types**
    uint8 public constant ACCESS_TYPE_ONE_TIME = 1;
    uint8 public constant ACCESS_TYPE_SUBSCRIPTION = 2;
    uint8 public constant ACCESS_TYPE_PERPETUAL = 3;

    // **Payment Model Types**
    uint8 public constant PAYMENT_MODEL_FIXED = 1;
    uint8 public constant PAYMENT_MODEL_PER_QUERY = 2;
    uint8 public constant PAYMENT_MODEL_REVENUE_SHARE = 3;

    // **Listing States**
    uint8 public constant LISTING_STATE_ACTIVE = 1;
    uint8 public constant LISTING_STATE_PAUSED = 2;
    uint8 public constant LISTING_STATE_CLOSED = 3;

    // **Protocol Fee Constants**
    uint16 public constant MAX_PROTOCOL_FEE = 2000; // 20% in basis points

    // ==========================================================================
    // State Variables
    // ==========================================================================

    // **Contract References**
    IDataVaultNFT public dataVaultContract;
    IPrivaToken public privaToken;

    // **Fee Configuration**
    uint16 public protocolFeeRate; // Basis points (e.g., 500 = 5%)
    address public feeCollector;

    // **Marketplace Statistics**
    uint256 public totalTransactions;
    uint256 public totalVolume;
    uint256 public totalListings;

    // **Market Listings Structure**
    struct Listing {
        uint256 dataVaultId;     // ID of the DataVault NFT
        address owner;           // Owner of the DataVault
        uint256 price;           // Base price in PRIVA tokens
        uint8 accessType;        // Type of access being offered
        uint8 paymentModel;      // Payment model for this listing
        uint256 subscriptionPeriod; // Period in seconds (for subscription model)
        string accessRequirements; // Additional requirements (e.g., "academic research only")
        string dataDescription;  // Description of the data being offered
        string[] dataTags;       // Tags for searchability
        uint8 state;             // Current state of the listing
        bool verificationRequired; // Whether researcher verification is required
        uint256 revenueSharePercentage; // Percentage for revenue share model (basis points)
        uint256 createdAt;       // Timestamp when listing was created
        uint256 updatedAt;       // Timestamp when listing was last updated
    }

    // **Researcher Verification Structure**
    struct ResearcherVerification {
        address researcher;
        string organization;
        string credentials;
        bool verified;
        address verifier;
        uint256 verifiedAt;
    }

    // **Access Request Structure**
    struct AccessRequest {
        uint256 listingId;
        address researcher;
        string purpose;
        uint256 offeredPrice;
        uint256 requestedAt;
        bool approved;
        uint256 approvedAt;
        uint256 expiresAt;
        string denialReason;
    }

    // **Transaction Record Structure**
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

    // **Mappings**
    mapping(uint256 => Listing) public listings;
    mapping(address => uint256[]) private _userListings;
    mapping(uint256 => uint256) private _dataVaultToListing;

    mapping(address => ResearcherVerification) public researcherVerifications;
    mapping(address => address[]) private _verifierHistory;

    mapping(uint256 => AccessRequest[]) public accessRequests;
    mapping(address => uint256[]) private _userAccessRequests;

    mapping(uint256 => Transaction[]) public listingTransactions;
    mapping(address => Transaction[]) private _userTransactions;

    // **Category System**
    mapping(string => uint256[]) private _listingsByCategory;
    mapping(string => uint256) public categoryListingCount;
    string[] public categories;

    // **Active Access Tracking**
    mapping(address => mapping(uint256 => uint256)) private _activeAccess; // researcher => dataVaultId => expiration

    // **Revenue Tracking for Revenue Share Model**
    mapping(uint256 => uint256) public listingRevenue; // listingId => total revenue
    mapping(uint256 => mapping(address => uint256)) public researcherSpending; // listingId => researcher => amount spent

    // ==========================================================================
    // Events
    // ==========================================================================

    event ListingCreated(uint256 indexed listingId, uint256 indexed dataVaultId, address indexed owner, uint256 price, uint8 accessType);
    event ListingUpdated(uint256 indexed listingId, uint256 price, uint8 state);
    event ListingClosed(uint256 indexed listingId, uint256 indexed dataVaultId, address indexed owner);
    event AccessRequested(uint256 indexed listingId, address indexed researcher, string purpose, uint256 offeredPrice);
    event AccessApproved(uint256 indexed listingId, address indexed researcher, uint256 expiresAt);
    event AccessDenied(uint256 indexed listingId, address indexed researcher, string reason);
    event TransactionExecuted(uint256 indexed listingId, uint256 indexed dataVaultId, address indexed buyer, address seller, uint256 price, uint8 accessType);
    event ResearcherVerified(address indexed researcher, address indexed verifier, string organization);
    event CategoryAdded(string category);
    event ProtocolFeeUpdated(uint16 oldFee, uint16 newFee);
    event FeeCollectorUpdated(address oldCollector, address newCollector);

    // ==========================================================================
    // Constructor
    // ==========================================================================

    /**
     * @dev Initializes the Data Marketplace contract.
     * @param _dataVaultContract Address of the DataVault NFT contract
     * @param _privaToken Address of the PRIVA token contract
     * @param _feeCollector Address where protocol fees will be sent
     * @param _initialProtocolFee Initial protocol fee rate in basis points
     */
    constructor(
        address _dataVaultContract,
        address _privaToken,
        address _feeCollector,
        uint16 _initialProtocolFee
    ) {
        require(_dataVaultContract != address(0), "Invalid DataVault contract address");
        require(_privaToken != address(0), "Invalid PRIVA token address");
        require(_feeCollector != address(0), "Invalid fee collector address");
        require(_initialProtocolFee <= MAX_PROTOCOL_FEE, "Fee exceeds maximum");

        dataVaultContract = IDataVaultNFT(_dataVaultContract);
        privaToken = IPrivaToken(_privaToken);
        feeCollector = _feeCollector;
        protocolFeeRate = _initialProtocolFee;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MARKETPLACE_ADMIN_ROLE, msg.sender);
        _grantRole(FEE_MANAGER_ROLE, msg.sender);
        _grantRole(VERIFICATION_ROLE, msg.sender);

        // Initialize default categories
        _addCategory("Medical");
        _addCategory("Financial");
        _addCategory("Personal");
        _addCategory("Behavioral");
        _addCategory("Location");
        _addCategory("Professional");
        _addCategory("Educational");
        _addCategory("Social Media");
    }

    // ==========================================================================
    // Listing Management
    // ==========================================================================

    /**
     * @dev Create a new listing for a DataVault NFT.
     * @param dataVaultId ID of the DataVault NFT to list
     * @param price Base price in PRIVA tokens
     * @param accessType Type of access being offered
     * @param paymentModel Payment model for this listing
     * @param subscriptionPeriod Period in seconds (for subscription model)
     * @param accessRequirements Additional requirements
     * @param dataDescription Description of the data
     * @param dataTags Tags for searchability
     * @param verificationRequired Whether researcher verification is required
     * @param revenueSharePercentage Percentage for revenue share model
     * @param category Main category for the listing
     * @return listingId ID of the created listing
     */
    function createListing(
        uint256 dataVaultId,
        uint256 price,
        uint8 accessType,
        uint8 paymentModel,
        uint256 subscriptionPeriod,
        string memory accessRequirements,
        string memory dataDescription,
        string[] memory dataTags,
        bool verificationRequired,
        uint256 revenueSharePercentage,
        string memory category
    ) 
        external
        whenNotPaused
        nonReentrant
        returns (uint256)
    {
        require(privaToken.hasMarketplaceAccess(msg.sender), "Caller lacks marketplace access");
        require(dataVaultContract.ownerOf(dataVaultId) == msg.sender, "Caller is not the DataVault owner");
        require(_dataVaultToListing[dataVaultId] == 0, "DataVault already listed");

        require(accessType >= ACCESS_TYPE_ONE_TIME && accessType <= ACCESS_TYPE_PERPETUAL, "Invalid access type");
        require(paymentModel >= PAYMENT_MODEL_FIXED && paymentModel <= PAYMENT_MODEL_REVENUE_SHARE, "Invalid payment model");

        if (accessType == ACCESS_TYPE_SUBSCRIPTION) {
            require(subscriptionPeriod > 0, "Subscription period must be positive");
        }
        if (paymentModel == PAYMENT_MODEL_REVENUE_SHARE) {
            require(revenueSharePercentage > 0 && revenueSharePercentage <= 10000, "Invalid revenue share percentage");
        }

        bool categoryExists = false;
        for (uint256 i = 0; i < categories.length; i++) {
            if (keccak256(bytes(categories[i])) == keccak256(bytes(category))) {
                categoryExists = true;
                break;
            }
        }
        require(categoryExists, "Category does not exist");

        totalListings++;
        uint256 listingId = totalListings;

        listings[listingId] = Listing({
            dataVaultId: dataVaultId,
            owner: msg.sender,
            price: price,
            accessType: accessType,
            paymentModel: paymentModel,
            subscriptionPeriod: subscriptionPeriod,
            accessRequirements: accessRequirements,
            dataDescription: dataDescription,
            dataTags: dataTags,
            state: LISTING_STATE_ACTIVE,
            verificationRequired: verificationRequired,
            revenueSharePercentage: revenueSharePercentage,
            createdAt: block.timestamp,
            updatedAt: block.timestamp
        });

        _userListings[msg.sender].push(listingId);
        _dataVaultToListing[dataVaultId] = listingId;
        _listingsByCategory[category].push(listingId);
        categoryListingCount[category]++;

        emit ListingCreated(listingId, dataVaultId, msg.sender, price, accessType);
        return listingId;
    }

    /**
     * @dev Update an existing listing.
     * @param listingId ID of the listing to update
     * @param price New base price
     * @param state New listing state
     * @param verificationRequired New verification requirement
     * @param accessRequirements New access requirements
     * @param dataDescription New data description
     * @param dataTags New data tags
     */
    function updateListing(
        uint256 listingId,
        uint256 price,
        uint8 state,
        bool verificationRequired,
        string memory accessRequirements,
        string memory dataDescription,
        string[] memory dataTags
    ) 
        external
        whenNotPaused
        nonReentrant
    {
        Listing storage listing = listings[listingId];
        require(listing.owner != address(0), "Listing does not exist");
        require(listing.owner == msg.sender, "Not the listing owner");
        require(state >= LISTING_STATE_ACTIVE && state <= LISTING_STATE_CLOSED, "Invalid listing state");

        listing.price = price;
        listing.state = state;
        listing.verificationRequired = verificationRequired;
        listing.accessRequirements = accessRequirements;
        listing.dataDescription = dataDescription;
        listing.dataTags = dataTags;
        listing.updatedAt = block.timestamp;

        emit ListingUpdated(listingId, price, state);

        if (state == LISTING_STATE_CLOSED) {
            _closeListing(listingId);
        }
    }

    /**
     * @dev Close a listing, removing it from the marketplace.
     * @param listingId ID of the listing to close
     */
    function closeListing(uint256 listingId) 
        external 
        whenNotPaused
        nonReentrant
    {
        Listing storage listing = listings[listingId];
        require(listing.owner != address(0), "Listing does not exist");
        require(listing.owner == msg.sender || hasRole(MARKETPLACE_ADMIN_ROLE, msg.sender), "Not authorized to close listing");

        _closeListing(listingId);
    }

    /**
     * @dev Internal function to close a listing.
     * @param listingId ID of the listing to close
     */
    function _closeListing(uint256 listingId) private {
        Listing storage listing = listings[listingId];
        listing.state = LISTING_STATE_CLOSED;
        listing.updatedAt = block.timestamp;

        _dataVaultToListing[listing.dataVaultId] = 0;

        string memory category = _getCategoryForListing(listingId);
        if (bytes(category).length > 0) {
            categoryListingCount[category]--;
        }

        emit ListingClosed(listingId, listing.dataVaultId, listing.owner);
    }

    /**
     * @dev Helper function to get the category for a listing.
     * @param listingId ID of the listing
     * @return The category string
     */
    function _getCategoryForListing(uint256 listingId) private view returns (string memory) {
        for (uint256 i = 0; i < categories.length; i++) {
            string memory category = categories[i];
            uint256[] memory categoryListings = _listingsByCategory[category];
            for (uint256 j = 0; j < categoryListings.length; j++) {
                if (categoryListings[j] == listingId) {
                    return category;
                }
            }
        }
        return "";
    }

    /**
     * @dev Get all listings for a specific owner.
     * @param owner Address of the listing owner
     * @return Array of listing IDs owned by the address
     */
    function getListingsByOwner(address owner) external view returns (uint256[] memory) {
        return _userListings[owner];
    }

    /**
     * @dev Get all listings in a specific category.
     * @param category The category to query
     * @return Array of listing IDs in the category
     */
    function getListingsByCategory(string memory category) external view returns (uint256[] memory) {
        return _listingsByCategory[category];
    }

    /**
     * @dev Get listing ID for a DataVault NFT.
     * @param dataVaultId ID of the DataVault NFT
     * @return The listing ID, or 0 if not listed
     */
    function getListingForDataVault(uint256 dataVaultId) external view returns (uint256) {
        return _dataVaultToListing[dataVaultId];
    }

    /**
     * @dev Get all available categories.
     * @return Array of category strings
     */
    function getAllCategories() external view returns (string[] memory) {
        return categories;
    }

    // ==========================================================================
    // Access Request and Approval
    // ==========================================================================

    /**
     * @dev Request access to a listed DataVault.
     * @param listingId ID of the listing
     * @param purpose Research purpose description
     * @param offeredPrice Price offered for access (for negotiation)
     * @return Index of the created request
     */
    function requestAccess(
        uint256 listingId,
        string memory purpose,
        uint256 offeredPrice
    ) 
        external
        whenNotPaused
        nonReentrant
        returns (uint256)
    {
        Listing storage listing = listings[listingId];
        require(listing.owner != address(0), "Listing does not exist");
        require(listing.state == LISTING_STATE_ACTIVE, "Listing is not active");

        if (listing.verificationRequired) {
            require(researcherVerifications[msg.sender].verified, "Researcher verification required");
        }

        AccessRequest memory request = AccessRequest({
            listingId: listingId,
            researcher: msg.sender,
            purpose: purpose,
            offeredPrice: offeredPrice,
            requestedAt: block.timestamp,
            approved: false,
            approvedAt: 0,
            expiresAt: 0,
            denialReason: ""
        });

        accessRequests[listingId].push(request);
        uint256 requestId = accessRequests[listingId].length - 1;
        _userAccessRequests[msg.sender].push(listingId);

        emit AccessRequested(listingId, msg.sender, purpose, offeredPrice);
        return requestId;
    }

    /**
     * @dev Approve an access request.
     * @param listingId ID of the listing
     * @param requestId Index of the access request
     * @param agreedPrice Final agreed price
     */
    function approveAccess(
        uint256 listingId,
        uint256 requestId,
        uint256 agreedPrice
    ) 
        external
        whenNotPaused
        nonReentrant
    {
        Listing storage listing = listings[listingId];
        require(listing.owner != address(0), "Listing does not exist");
        require(listing.state == LISTING_STATE_ACTIVE, "Listing is not active");
        require(listing.owner == msg.sender, "Not the listing owner");

        require(requestId < accessRequests[listingId].length, "Request does not exist");
        AccessRequest storage request = accessRequests[listingId][requestId];
        require(!request.approved, "Request already approved");

        uint256 expiresAt;
        if (listing.accessType == ACCESS_TYPE_ONE_TIME) {
            expiresAt = block.timestamp + 1 days;
        } else if (listing.accessType == ACCESS_TYPE_SUBSCRIPTION) {
            expiresAt = block.timestamp + listing.subscriptionPeriod;
        } else {
            expiresAt = type(uint256).max;
        }

        request.approved = true;
        request.approvedAt = block.timestamp;
        request.expiresAt = expiresAt;
        _activeAccess[request.researcher][listing.dataVaultId] = expiresAt;

        emit AccessApproved(listingId, request.researcher, expiresAt);
        _executeTransaction(listingId, request.researcher, agreedPrice);
    }

    /**
     * @dev Deny an access request.
     * @param listingId ID of the listing
     * @param requestId Index of the access request
     * @param reason Reason for denial
     */
    function denyAccess(
        uint256 listingId,
        uint256 requestId,
        string memory reason
    ) 
        external
        whenNotPaused
        nonReentrant
    {
        Listing storage listing = listings[listingId];
        require(listing.owner != address(0), "Listing does not exist");
        require(listing.owner == msg.sender, "Not the listing owner");

        require(requestId < accessRequests[listingId].length, "Request does not exist");
        AccessRequest storage request = accessRequests[listingId][requestId];
        require(!request.approved, "Request already approved");

        request.denialReason = reason;
        emit AccessDenied(listingId, request.researcher, reason);
    }

    /**
     * @dev Check if a researcher has active access to a DataVault.
     * @param researcher Address of the researcher
     * @param dataVaultId ID of the DataVault NFT
     * @return True if access is active
     */
    function hasActiveAccess(address researcher, uint256 dataVaultId) external view returns (bool) {
        return _activeAccess[researcher][dataVaultId] > block.timestamp;
    }

    /**
     * @dev Get access expiration time for a researcher and DataVault.
     * @param researcher Address of the researcher
     * @param dataVaultId ID of the DataVault NFT
     * @return Expiration timestamp
     */
    function getAccessExpiration(address researcher, uint256 dataVaultId) external view returns (uint256) {
        return _activeAccess[researcher][dataVaultId];
    }

    /**
     * @dev Get all access requests for a listing.
     * @param listingId ID of the listing
     * @return Array of access requests
     */
    function getAccessRequests(uint256 listingId) external view returns (AccessRequest[] memory) {
        return accessRequests[listingId];
    }

    /**
     * @dev Get all access requests made by a researcher.
     * @param researcher Address of the researcher
     * @return Array of listing IDs requested
     */
    function getRequestsByResearcher(address researcher) external view returns (uint256[] memory) {
        return _userAccessRequests[researcher];
    }

    // ==========================================================================
    // Transaction Execution
    // ==========================================================================

    /**
     * @dev Execute a transaction for DataVault access.
     * @param listingId ID of the listing
     * @param buyer Address of the buyer
     * @param price Agreed price for the transaction
     */
    function _executeTransaction(
        uint256 listingId,
        address buyer,
        uint256 price
    ) private {
        Listing storage listing = listings[listingId];
        address seller = listing.owner;

        uint16 buyerFeeRate = privaToken.getApplicableFeeRate(buyer);
        uint256 protocolFee = price.mul(buyerFeeRate).div(10000);
        uint256 sellerAmount = price.sub(protocolFee);

        require(privaToken.transferFrom(buyer, address(this), price), "Token transfer failed");
        require(privaToken.transfer(seller, sellerAmount), "Seller payment failed");
        if (protocolFee > 0) {
            require(privaToken.transfer(feeCollector, protocolFee), "Fee transfer failed");
        }

        uint256 expiresAt;
        if (listing.accessType == ACCESS_TYPE_ONE_TIME) {
            expiresAt = block.timestamp + 1 days;
        } else if (listing.accessType == ACCESS_TYPE_SUBSCRIPTION) {
            expiresAt = block.timestamp + listing.subscriptionPeriod;
        } else {
            expiresAt = type(uint256).max;
        }

        Transaction memory transaction = Transaction({
            listingId: listingId,
            dataVaultId: listing.dataVaultId,
            seller: seller,
            buyer: buyer,
            price: price,
            accessType: listing.accessType,
            timestamp: block.timestamp,
            protocolFee: protocolFee,
            expiresAt: expiresAt
        });

        listingTransactions[listingId].push(transaction);
        _userTransactions[buyer].push(transaction);

        totalTransactions++;
        totalVolume = totalVolume.add(price);

        if (listing.paymentModel == PAYMENT_MODEL_REVENUE_SHARE) {
            listingRevenue[listingId] = listingRevenue[listingId].add(price);
            researcherSpending[listingId][buyer] = researcherSpending[listingId][buyer].add(price);
        }

        emit TransactionExecuted(listingId, listing.dataVaultId, buyer, seller, price, listing.accessType);
    }

    /**
     * @dev Direct purchase for fixed-price listings (no approval needed).
     * @param listingId ID of the listing to purchase
     * @return True if successful
     */
    function directPurchase(uint256 listingId) 
        external
        whenNotPaused
        nonReentrant
        returns (bool)
    {
        Listing storage listing = listings[listingId];
        require(listing.owner != address(0), "Listing does not exist");
        require(listing.state == LISTING_STATE_ACTIVE, "Listing is not active");
        require(listing.paymentModel == PAYMENT_MODEL_FIXED, "Only available for fixed price listings");

        if (listing.verificationRequired) {
            require(researcherVerifications[msg.sender].verified, "Researcher verification required");
        }

        uint256 expiresAt;
        if (listing.accessType == ACCESS_TYPE_ONE_TIME) {
            expiresAt = block.timestamp + 1 days;
        } else if (listing.accessType == ACCESS_TYPE_SUBSCRIPTION) {
            expiresAt = block.timestamp + listing.subscriptionPeriod;
        } else {
            expiresAt = type(uint256).max;
        }

        _activeAccess[msg.sender][listing.dataVaultId] = expiresAt;
        _executeTransaction(listingId, msg.sender, listing.price);
        return true;
    }

    /**
     * @dev Record a query execution for per-query payment model.
     * @param listingId ID of the listing
     * @param researcher Address of the researcher
     * @return True if successful
     */
    function recordQuery(uint256 listingId, address researcher)
        external
        whenNotPaused
        nonReentrant
        returns (bool)
    {
        Listing storage listing = listings[listingId];
        require(listing.owner != address(0), "Listing does not exist");
        require(listing.state == LISTING_STATE_ACTIVE, "Listing is not active");
        require(listing.paymentModel == PAYMENT_MODEL_PER_QUERY, "Only available for per-query listings");
        require(listing.owner == msg.sender || hasRole(MARKETPLACE_ADMIN_ROLE, msg.sender), "Not authorized to record query");
        require(_activeAccess[researcher][listing.dataVaultId] > block.timestamp, "Researcher has no active access");

        _executeTransaction(listingId, researcher, listing.price);
        return true;
    }

    /**
     * @dev Get transactions for a listing.
     * @param listingId ID of the listing
     * @return Array of transactions
     */
    function getListingTransactions(uint256 listingId) external view returns (Transaction[] memory) {
        return listingTransactions[listingId];
    }

    /**
     * @dev Get transactions for a user (buyer).
     * @param user Address of the user
     * @return Array of transactions
     */
    function getUserTransactions(address user) external view returns (Transaction[] memory) {
        return _userTransactions[user];
    }

    // ==========================================================================
    // Researcher Verification
    // ==========================================================================

    /**
     * @dev Submit researcher credentials for verification.
     * @param organization Organization the researcher belongs to
     * @param credentials Description of researcher credentials
     * @return True if successful
     */
    function submitResearcherCredentials(
        string memory organization,
        string memory credentials
    ) 
        external
        whenNotPaused
        returns (bool)
    {
        researcherVerifications[msg.sender] = ResearcherVerification({
            researcher: msg.sender,
            organization: organization,
            credentials: credentials,
            verified: false,
            verifier: address(0),
            verifiedAt: 0
        });
        return true;
    }

    /**
     * @dev Verify a researcher's credentials.
     * @param researcher Address of the researcher to verify
     * @return True if successful
     */
    function verifyResearcher(address researcher) 
        external
        onlyRole(VERIFICATION_ROLE)
        whenNotPaused
        returns (bool)
    {
        ResearcherVerification storage verification = researcherVerifications[researcher];
        require(verification.researcher == researcher, "Researcher has not submitted credentials");

        verification.verified = true;
        verification.verifier = msg.sender;
        verification.verifiedAt = block.timestamp;

        _verifierHistory[researcher].push(msg.sender);
        emit ResearcherVerified(researcher, msg.sender, verification.organization);
        return true;
    }

    /**
     * @dev Revoke a researcher's verification.
     * @param researcher Address of the researcher
     * @return True if successful
     */
    function revokeVerification(address researcher)
        external
        onlyRole(VERIFICATION_ROLE)
        whenNotPaused
        returns (bool)
    {
        ResearcherVerification storage verification = researcherVerifications[researcher];
        require(verification.verified, "Researcher is not verified");

        verification.verified = false;
        return true;
    }

    /**
     * @dev Check if a researcher is verified.
     * @param researcher Address of the researcher
     * @return Whether the researcher is verified
     */
    function isResearcherVerified(address researcher) external view returns (bool) {
        return researcherVerifications[researcher].verified;
    }

    /**
     * @dev Get verification history for a researcher.
     * @param researcher Address of the researcher
     * @return Array of verifier addresses
     */
    function getVerificationHistory(address researcher) external view returns (address[] memory) {
        return _verifierHistory[researcher];
    }

    // ==========================================================================
    // Category Management
    // ==========================================================================

    /**
     * @dev Add a new category to the marketplace.
     * @param category Name of the category
     * @return True if successful
     */
    function addCategory(string memory category)
        external
        onlyRole(MARKETPLACE_ADMIN_ROLE)
        returns (bool)
    {
        return _addCategory(category);
    }

    /**
     * @dev Internal function to add a category.
     * @param category Name of the category
     * @return True if successful
     */
    function _addCategory(string memory category) private returns (bool) {
        for (uint256 i = 0; i < categories.length; i++) {
            if (keccak256(bytes(categories[i])) == keccak256(bytes(category))) {
                return false;
            }
        }

        categories.push(category);
        emit CategoryAdded(category);
        return true;
    }

    // ==========================================================================
    // Fee Management
    // ==========================================================================

    /**
     * @dev Update the protocol fee rate.
     * @param newFeeRate New protocol fee rate in basis points
     */
    function setProtocolFeeRate(uint16 newFeeRate)
        external
        onlyRole(FEE_MANAGER_ROLE)
    {
        require(newFeeRate <= MAX_PROTOCOL_FEE, "Fee exceeds maximum");

        uint16 oldFeeRate = protocolFeeRate;
        protocolFeeRate = newFeeRate;
        emit ProtocolFeeUpdated(oldFeeRate, newFeeRate);
    }

    /**
     * @dev Update the fee collector address.
     * @param newFeeCollector New fee collector address
     */
    function setFeeCollector(address newFeeCollector)
        external
        onlyRole(FEE_MANAGER_ROLE)
    {
        require(newFeeCollector != address(0), "Invalid fee collector address");

        address oldFeeCollector = feeCollector;
        feeCollector = newFeeCollector;
        emit FeeCollectorUpdated(oldFeeCollector, newFeeCollector);
    }

    // ==========================================================================
    // Admin Functions
    // ==========================================================================

    /**
     * @dev Pause the marketplace.
     */
    function pause() external onlyRole(MARKETPLACE_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @dev Unpause the marketplace.
     */
    function unpause() external onlyRole(MARKETPLACE_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @dev Withdraw any tokens accidentally sent to the contract.
     * @param token Address of the token to withdraw
     * @param amount Amount to withdraw
     */
    function withdrawToken(address token, uint256 amount)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(token != address(0), "Invalid token address");

        IERC20 tokenContract = IERC20(token);
        require(tokenContract.transfer(msg.sender, amount), "Token transfer failed");
    }
}
