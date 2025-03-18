// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title DataVaultNFT
 * @dev Core smart contract for PrivaSight DataVault NFTs
 * Represents encrypted personal data as NFTs with customizable access rules,
 * provenance tracking, and integration with the PRIVA token economy.
 */
contract DataVaultNFT is ERC721URIStorage, Ownable {
    using Counters for Counters.Counter;
    Counters.Counter private _tokenIds;

    IERC20 public privaToken;

    // Struct for DataVault core properties
    struct DataVault {
        string dataHash;         // IPFS/Secret Network pointer to encrypted data
        string encryptionKeyHash; // Hash of the encryption key (for verification)
        string accessRules;      // JSON string defining access permissions
        string dataCategory;     // Category (e.g., "medical", "financial")
        uint256 stakingAmount;   // Amount of PRIVA tokens staked on this vault
        uint256 lastUpdated;     // Timestamp of last update
    }

    // Struct for access requests from researchers
    struct AccessRequest {
        address requester;
        string purpose;
        uint256 compensation;
        uint256 requestTime;
        bool approved;
        bool completed;
        string resultHash;       // Hash of computation results
    }

    // Mappings for storage
    mapping(uint256 => DataVault) public dataVaults;                           // Token ID to DataVault
    mapping(uint256 => mapping(address => bool)) public authorizedResearchers; // Token ID to researcher access
    mapping(uint256 => uint256) public timesAccessed;                          // Token ID to access count
    mapping(uint256 => uint256) public tokensEarned;                           // Token ID to tokens earned
    mapping(uint256 => mapping(string => uint256)) public categoryAccess;      // Token ID to category access count
    mapping(uint256 => mapping(uint256 => AccessRequest)) public accessRequests; // Token ID to request ID to AccessRequest
    mapping(uint256 => uint256) public accessRequestCount;                     // Token ID to number of access requests
    mapping(address => bool) public verifiedResearchers;                       // Verified researcher status

    // Events
    event DataVaultMinted(uint256 indexed tokenId, address owner, string dataCategory);
    event AccessRequested(uint256 indexed tokenId, uint256 requestId, address requester, string purpose);
    event AccessGranted(uint256 indexed tokenId, address requester);
    event AccessRevoked(uint256 indexed tokenId, address researcher);
    event StakeAdded(uint256 indexed tokenId, uint256 amount);
    event ResultsPublished(uint256 indexed tokenId, uint256 requestId, string resultHash);
    event MetadataUpdated(uint256 indexed tokenId, string newMetadataURI);

    constructor(address _privaTokenAddress) ERC721("PrivaSight DataVault", "PDV") {
        privaToken = IERC20(_privaTokenAddress);
    }

    /**
     * @dev Mint a new DataVault NFT
     * @param _dataHash IPFS/Secret Network hash pointing to the encrypted data
     * @param _encryptionKeyHash Hash of the encryption key used (stored off-chain)
     * @param _accessRules JSON string defining access permissions
     * @param _dataCategory Category of the data (e.g., "medical", "financial")
     * @param _metadataURI URI pointing to additional NFT metadata
     * @param _stakingAmount Amount of PRIVA tokens to stake on this vault
     * @return uint256 The new token ID
     */
    function mintDataVault(
        string memory _dataHash,
        string memory _encryptionKeyHash,
        string memory _accessRules,
        string memory _dataCategory,
        string memory _metadataURI,
        uint256 _stakingAmount
    ) public returns (uint256) {
        require(bytes(_dataHash).length > 0, "Data hash cannot be empty");

        if (_stakingAmount > 0) {
            require(
                privaToken.transferFrom(msg.sender, address(this), _stakingAmount),
                "Token transfer failed"
            );
        }

        _tokenIds.increment();
        uint256 newTokenId = _tokenIds.current();

        dataVaults[newTokenId] = DataVault({
            dataHash: _dataHash,
            encryptionKeyHash: _encryptionKeyHash,
            accessRules: _accessRules,
            dataCategory: _dataCategory,
            stakingAmount: _stakingAmount,
            lastUpdated: block.timestamp
        });

        timesAccessed[newTokenId] = 0;
        tokensEarned[newTokenId] = 0;

        _safeMint(msg.sender, newTokenId);
        _setTokenURI(newTokenId, _metadataURI);

        emit DataVaultMinted(newTokenId, msg.sender, _dataCategory);

        return newTokenId;
    }

    /**
     * @dev Update access rules for a DataVault
     * @param _tokenId Token ID of the DataVault
     * @param _newRules New access rules JSON string
     */
    function updateAccessRules(uint256 _tokenId, string memory _newRules) public {
        require(_exists(_tokenId), "DataVault does not exist");
        require(ownerOf(_tokenId) == msg.sender, "Only owner can update rules");

        dataVaults[_tokenId].accessRules = _newRules;
        dataVaults[_tokenId].lastUpdated = block.timestamp;
    }

    /**
     * @dev Update the data hash and encryption key hash
     * @param _tokenId Token ID of the DataVault
     * @param _newDataHash New data hash
     * @param _newEncryptionKeyHash New encryption key hash
     */
    function updateDataHash(
        uint256 _tokenId,
        string memory _newDataHash,
        string memory _newEncryptionKeyHash
    ) public {
        require(_exists(_tokenId), "DataVault does not exist");
        require(ownerOf(_tokenId) == msg.sender, "Only owner can update data");

        dataVaults[_tokenId].dataHash = _newDataHash;
        dataVaults[_tokenId].encryptionKeyHash = _newEncryptionKeyHash;
        dataVaults[_tokenId].lastUpdated = block.timestamp;
    }

    /**
     * @dev Update the metadata URI for a DataVault
     * @param _tokenId Token ID of the DataVault
     * @param _newMetadataURI New metadata URI
     */
    function updateMetadataURI(uint256 _tokenId, string memory _newMetadataURI) public {
        require(_exists(_tokenId), "DataVault does not exist");
        require(ownerOf(_tokenId) == msg.sender, "Only owner can update metadata");

        _setTokenURI(_tokenId, _newMetadataURI);
        emit MetadataUpdated(_tokenId, _newMetadataURI);
    }

    /**
     * @dev Add PRIVA tokens to stake on a DataVault
     * @param _tokenId Token ID of the DataVault
     * @param _amount Amount of PRIVA tokens to stake
     */
    function addStake(uint256 _tokenId, uint256 _amount) public {
        require(_exists(_tokenId), "DataVault does not exist");
        require(ownerOf(_tokenId) == msg.sender, "Only owner can stake");
        require(_amount > 0, "Stake amount must be greater than zero");

        require(
            privaToken.transferFrom(msg.sender, address(this), _amount),
            "Token transfer failed"
        );

        dataVaults[_tokenId].stakingAmount += _amount;

        emit StakeAdded(_tokenId, _amount);
    }

    /**
     * @dev Request access to a DataVault for research
     * @param _tokenId Token ID of the DataVault
     * @param _purpose Research purpose description
     * @param _compensation Offered PRIVA token compensation
     */
    function requestAccess(
        uint256 _tokenId,
        string memory _purpose,
        uint256 _compensation
    ) public {
        require(_exists(_tokenId), "DataVault does not exist");
        require(_compensation > 0, "Compensation must be greater than zero");

        // Uncomment below to require verified researchers
        // require(verifiedResearchers[msg.sender], "Researcher not verified");

        uint256 requestId = accessRequestCount[_tokenId];
        accessRequests[_tokenId][requestId] = AccessRequest({
            requester: msg.sender,
            purpose: _purpose,
            compensation: _compensation,
            requestTime: block.timestamp,
            approved: false,
            completed: false,
            resultHash: ""
        });

        accessRequestCount[_tokenId]++;

        emit AccessRequested(_tokenId, requestId, msg.sender, _purpose);
    }

    /**
     * @dev Approve an access request
     * @param _tokenId Token ID of the DataVault
     * @param _requestId ID of the access request
     */
    function approveAccess(uint256 _tokenId, uint256 _requestId) public {
        require(_exists(_tokenId), "DataVault does not exist");
        require(ownerOf(_tokenId) == msg.sender, "Only owner can approve access");
        require(_requestId < accessRequestCount[_tokenId], "Invalid request ID");

        AccessRequest storage request = accessRequests[_tokenId][_requestId];
        require(!request.approved, "Request already approved");

        request.approved = true;
        authorizedResearchers[_tokenId][request.requester] = true;

        emit AccessGranted(_tokenId, request.requester);
    }

    /**
     * @dev Revoke access for a researcher
     * @param _tokenId Token ID of the DataVault
     * @param _researcher Address of the researcher
     */
    function revokeAccess(uint256 _tokenId, address _researcher) public {
        require(_exists(_tokenId), "DataVault does not exist");
        require(ownerOf(_tokenId) == msg.sender, "Only owner can revoke access");
        require(authorizedResearchers[_tokenId][_researcher], "Researcher not authorized");

        authorizedResearchers[_tokenId][_researcher] = false;

        emit AccessRevoked(_tokenId, _researcher);
    }

    /**
     * @dev Publish research results and distribute compensation
     * @param _tokenId Token ID of the DataVault
     * @param _requestId ID of the access request
     * @param _resultHash Hash of the computation results
     */
    function publishResults(
        uint256 _tokenId,
        uint256 _requestId,
        string memory _resultHash
    ) public {
        require(_exists(_tokenId), "DataVault does not exist");
        require(_requestId < accessRequestCount[_tokenId], "Invalid request ID");

        AccessRequest storage request = accessRequests[_tokenId][_requestId];
        require(request.requester == msg.sender, "Only requester can publish results");
        require(request.approved, "Access not approved");
        require(!request.completed, "Request already completed");

        request.completed = true;
        request.resultHash = _resultHash;

        timesAccessed[_tokenId]++;
        tokensEarned[_tokenId] += request.compensation;
        categoryAccess[_tokenId][dataVaults[_tokenId].dataCategory]++;

        require(
            privaToken.transferFrom(msg.sender, ownerOf(_tokenId), request.compensation),
            "Token transfer failed"
        );

        emit ResultsPublished(_tokenId, _requestId, _resultHash);
    }

    /**
     * @dev Check if a researcher has access to a DataVault
     * @param _tokenId Token ID of the DataVault
     * @param _researcher Address of the researcher
     * @return bool Whether the researcher has access
     */
    function hasAccess(uint256 _tokenId, address _researcher) public view returns (bool) {
        require(_exists(_tokenId), "DataVault does not exist");
        return authorizedResearchers[_tokenId][_researcher];
    }

    /**
     * @dev Get usage statistics for a DataVault
     * @param _tokenId Token ID of the DataVault
     * @return timesAccessed Number of times accessed
     * @return tokensEarned Total tokens earned
     */
    function getUsageStatistics(uint256 _tokenId) public view returns (uint256, uint256) {
        require(_exists(_tokenId), "DataVault does not exist");
        return (timesAccessed[_tokenId], tokensEarned[_tokenId]);
    }

    /**
     * @dev Get DataVault core properties
     * @param _tokenId Token ID of the DataVault
     * @return dataHash IPFS/Secret Network hash
     * @return accessRules Access rules JSON
     * @return dataCategory Data category
     * @return stakingAmount Amount of PRIVA tokens staked
     * @return lastUpdated Last update timestamp
     */
    function getDataVaultInfo(uint256 _tokenId)
        public
        view
        returns (string memory, string memory, string memory, uint256, uint256)
    {
        require(_exists(_tokenId), "DataVault does not exist");
        DataVault memory vault = dataVaults[_tokenId];
        return (
            vault.dataHash,
            vault.accessRules,
            vault.dataCategory,
            vault.stakingAmount,
            vault.lastUpdated
        );
    }

    /**
     * @dev Register a verified researcher (only owner)
     * @param _researcher Address of the researcher
     */
    function registerResearcher(address _researcher) public onlyOwner {
        verifiedResearchers[_researcher] = true;
    }

    /**
     * @dev Unregister a verified researcher (only owner)
     * @param _researcher Address of the researcher
     */
    function unregisterResearcher(address _researcher) public onlyOwner {
        verifiedResearchers[_researcher] = false;
    }

    /**
     * @dev Update the PRIVA token address (only owner)
     * @param _newTokenAddress New token contract address
     */
    function updateTokenAddress(address _newTokenAddress) public onlyOwner {
        privaToken = IERC20(_newTokenAddress);
    }
}
