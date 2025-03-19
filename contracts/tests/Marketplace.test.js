const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("DataMarketplace", function () {
  // Contract instances
  let dataMarketplace;
  let dataVaultNFT;
  let privaToken;
  
  // Mock addresses and variables
  let owner;
  let dataOwner1;
  let dataOwner2;
  let researcher1;
  let researcher2;
  let verifier;
  let feeCollector;
  
  // Constants for testing
  const ZERO_ADDRESS = ethers.constants.AddressZero;
  const ONE_DAY = 24 * 60 * 60;
  const THIRTY_DAYS = 30 * ONE_DAY;
  
  // Token constants
  const TOKEN_DECIMALS = 18;
  const INITIAL_SUPPLY = ethers.utils.parseEther("1000000"); // 1 million tokens
  
  // DataVault and marketplace constants
  const DATAVAULT_COUNT = 5;
  const DEFAULT_PRICE = ethers.utils.parseEther("100");
  const SUBSCRIPTION_PERIOD = THIRTY_DAYS;
  
  // Access and payment model constants
  let ACCESS_TYPE_ONE_TIME;
  let ACCESS_TYPE_SUBSCRIPTION;
  let ACCESS_TYPE_PERPETUAL;
  let PAYMENT_MODEL_FIXED;
  let PAYMENT_MODEL_PER_QUERY;
  let PAYMENT_MODEL_REVENUE_SHARE;
  let LISTING_STATE_ACTIVE;
  let LISTING_STATE_PAUSED;
  let LISTING_STATE_CLOSED;
  
  // Categories
  const CATEGORY_MEDICAL = "Medical";
  const CATEGORY_FINANCIAL = "Financial";
  
  // Sample data
  const sampleDataHash = "QmSampleHashForEncryptedDataOnIPFS123456789";
  const sampleAccessRules = '{"allowedPurposes": ["medical_research"], "allowedOrganizations": ["Research Institute"]}';
  const sampleMetadataURI = "ipfs://QmSampleMetadataURI";
  const sampleAccessRequirements = "For medical research only. IRB approval required.";
  const sampleDataDescription = "De-identified patient data for diabetes research.";
  const sampleDataTags = ["diabetes", "patient", "clinical", "anonymous"];
  const sampleOrganization = "University Research Institute";
  const sampleCredentials = "PhD in Medical Sciences, IRB approval #12345";
  const samplePurpose = "Study on diabetes treatments effectiveness";
  
  beforeEach(async function () {
    // Get signers for different test roles
    [owner, dataOwner1, dataOwner2, researcher1, researcher2, verifier, feeCollector] = await ethers.getSigners();
    
    // Deploy PRIVA token
    const PrivaToken = await ethers.getContractFactory("PrivaToken");
    privaToken = await PrivaToken.deploy(INITIAL_SUPPLY, feeCollector.address);
    await privaToken.deployed();
    
    // Transfer tokens to test accounts
    await privaToken.transfer(dataOwner1.address, ethers.utils.parseEther("10000"));
    await privaToken.transfer(dataOwner2.address, ethers.utils.parseEther("10000"));
    await privaToken.transfer(researcher1.address, ethers.utils.parseEther("10000"));
    await privaToken.transfer(researcher2.address, ethers.utils.parseEther("10000"));
    
    // Deploy DataVaultNFT
    const DataVaultNFT = await ethers.getContractFactory("DataVaultNFT");
    dataVaultNFT = await DataVaultNFT.deploy(privaToken.address);
    await dataVaultNFT.deployed();
    
    // Deploy DataMarketplace
    const DataMarketplace = await ethers.getContractFactory("DataMarketplace");
    dataMarketplace = await DataMarketplace.deploy(
      dataVaultNFT.address,
      privaToken.address,
      feeCollector.address,
      500 // 5% protocol fee
    );
    await dataMarketplace.deployed();
    
    // Get constants from the marketplace
    ACCESS_TYPE_ONE_TIME = await dataMarketplace.ACCESS_TYPE_ONE_TIME();
    ACCESS_TYPE_SUBSCRIPTION = await dataMarketplace.ACCESS_TYPE_SUBSCRIPTION();
    ACCESS_TYPE_PERPETUAL = await dataMarketplace.ACCESS_TYPE_PERPETUAL();
    PAYMENT_MODEL_FIXED = await dataMarketplace.PAYMENT_MODEL_FIXED();
    PAYMENT_MODEL_PER_QUERY = await dataMarketplace.PAYMENT_MODEL_PER_QUERY();
    PAYMENT_MODEL_REVENUE_SHARE = await dataMarketplace.PAYMENT_MODEL_REVENUE_SHARE();
    LISTING_STATE_ACTIVE = await dataMarketplace.LISTING_STATE_ACTIVE();
    LISTING_STATE_PAUSED = await dataMarketplace.LISTING_STATE_PAUSED();
    LISTING_STATE_CLOSED = await dataMarketplace.LISTING_STATE_CLOSED();
    
    // Setup DataVaultNFTs for testing (create multiple vaults for different tests)
    await createTestDataVaults();
    
    // Approve marketplace to transfer PRIVA tokens from researchers
    await privaToken.connect(researcher1).approve(dataMarketplace.address, ethers.utils.parseEther("10000"));
    await privaToken.connect(researcher2).approve(dataMarketplace.address, ethers.utils.parseEther("10000"));
    
    // Grant marketplace access to all test users (in a real implementation, this would be based on PRIVA staking tiers)
    const MARKETPLACE_ACCESS_ROLE = await dataMarketplace.MARKETPLACE_ACCESS_ROLE();
    await dataMarketplace.grantRole(MARKETPLACE_ACCESS_ROLE, dataOwner1.address);
    await dataMarketplace.grantRole(MARKETPLACE_ACCESS_ROLE, dataOwner2.address);
    await dataMarketplace.grantRole(MARKETPLACE_ACCESS_ROLE, researcher1.address);
    await dataMarketplace.grantRole(MARKETPLACE_ACCESS_ROLE, researcher2.address);
    
    // Grant verifier role to verifier
    const VERIFICATION_ROLE = await dataMarketplace.VERIFICATION_ROLE();
    await dataMarketplace.grantRole(VERIFICATION_ROLE, verifier.address);
  });
  
  async function createTestDataVaults() {
    // Create multiple DataVaults with different owners and categories
    for (let i = 0; i < DATAVAULT_COUNT; i++) {
      // Alternate between medical and financial categories
      const category = i % 2 === 0 ? "medical" : "financial";
      const dataOwner = i % 2 === 0 ? dataOwner1 : dataOwner2;
      
      await dataVaultNFT.connect(dataOwner).mintDataVault(
        `${sampleDataHash}-${i}`,
        "0x" + "0".repeat(64), // Mock encryption key hash
        sampleAccessRules,
        category,
        `${sampleMetadataURI}-${i}`,
        0 // No initial staking
      );
    }
  }
  
  // ==========================================================================
  // Listing Management Tests
  // ==========================================================================
  
  describe("Listing Management", function () {
    it("Should create a new listing for a DataVault NFT", async function () {
      const dataVaultId = 1;
      const tx = await dataMarketplace.connect(dataOwner1).createListing(
        dataVaultId,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        true,
        0,
        CATEGORY_MEDICAL
      );
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "ListingCreated");
      const listingId = event.args.listingId;
      const listing = await dataMarketplace.listings(listingId);
      
      expect(listing.dataVaultId).to.equal(dataVaultId);
      expect(listing.owner).to.equal(dataOwner1.address);
      expect(listing.price).to.equal(DEFAULT_PRICE);
      expect(listing.accessType).to.equal(ACCESS_TYPE_ONE_TIME);
      expect(listing.paymentModel).to.equal(PAYMENT_MODEL_FIXED);
      expect(listing.dataDescription).to.equal(sampleDataDescription);
      expect(listing.state).to.equal(LISTING_STATE_ACTIVE);
      expect(listing.verificationRequired).to.equal(true);
      
      const listingsByOwner = await dataMarketplace.getListingsByOwner(dataOwner1.address);
      expect(listingsByOwner.length).to.equal(1);
      expect(listingsByOwner[0]).to.equal(listingId);
      
      const listingsByCategory = await dataMarketplace.getListingsByCategory(CATEGORY_MEDICAL);
      expect(listingsByCategory.length).to.equal(1);
      
      const listingForDataVault = await dataMarketplace.getListingForDataVault(dataVaultId);
      expect(listingForDataVault).to.equal(listingId);
    });
    
    it("Should create a subscription-based listing", async function () {
      const dataVaultId = 2;
      const tx = await dataMarketplace.connect(dataOwner1).createListing(
        dataVaultId,
        DEFAULT_PRICE,
        ACCESS_TYPE_SUBSCRIPTION,
        PAYMENT_MODEL_FIXED,
        SUBSCRIPTION_PERIOD,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        false,
        0,
        CATEGORY_MEDICAL
      );
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "ListingCreated");
      const listingId = event.args.listingId;
      const listing = await dataMarketplace.listings(listingId);
      
      expect(listing.accessType).to.equal(ACCESS_TYPE_SUBSCRIPTION);
      expect(listing.subscriptionPeriod).to.equal(SUBSCRIPTION_PERIOD);
    });
    
    it("Should create a revenue-share listing", async function () {
      const dataVaultId = 3;
      const revenueSharePercentage = 2000; // 20%
      const tx = await dataMarketplace.connect(dataOwner2).createListing(
        dataVaultId,
        DEFAULT_PRICE,
        ACCESS_TYPE_PERPETUAL,
        PAYMENT_MODEL_REVENUE_SHARE,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        true,
        revenueSharePercentage,
        CATEGORY_FINANCIAL
      );
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "ListingCreated");
      const listingId = event.args.listingId;
      const listing = await dataMarketplace.listings(listingId);
      
      expect(listing.paymentModel).to.equal(PAYMENT_MODEL_REVENUE_SHARE);
      expect(listing.revenueSharePercentage).to.equal(revenueSharePercentage);
    });
    
    it("Should update an existing listing", async function () {
      const dataVaultId = 1;
      const createTx = await dataMarketplace.connect(dataOwner1).createListing(
        dataVaultId,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        true,
        0,
        CATEGORY_MEDICAL
      );
      const createReceipt = await createTx.wait();
      const createEvent = createReceipt.events.find(event => event.event === "ListingCreated");
      const listingId = createEvent.args.listingId;
      
      const newPrice = ethers.utils.parseEther("150");
      const newState = LISTING_STATE_ACTIVE;
      const newVerificationRequired = false;
      const newAccessRequirements = "Updated access requirements";
      const newDataDescription = "Updated data description";
      const newDataTags = ["updated", "tags"];
      
      await dataMarketplace.connect(dataOwner1).updateListing(
        listingId,
        newPrice,
        newState,
        newVerificationRequired,
        newAccessRequirements,
        newDataDescription,
        newDataTags
      );
      
      const listing = await dataMarketplace.listings(listingId);
      expect(listing.price).to.equal(newPrice);
      expect(listing.verificationRequired).to.equal(newVerificationRequired);
      expect(listing.accessRequirements).to.equal(newAccessRequirements);
      expect(listing.dataDescription).to.equal(newDataDescription);
    });
    
    it("Should close a listing", async function () {
      const dataVaultId = 1;
      const createTx = await dataMarketplace.connect(dataOwner1).createListing(
        dataVaultId,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        true,
        0,
        CATEGORY_MEDICAL
      );
      const createReceipt = await createTx.wait();
      const createEvent = createReceipt.events.find(event => event.event === "ListingCreated");
      const listingId = createEvent.args.listingId;
      
      await dataMarketplace.connect(dataOwner1).closeListing(listingId);
      const listing = await dataMarketplace.listings(listingId);
      expect(listing.state).to.equal(LISTING_STATE_CLOSED);
      
      const listingForDataVault = await dataMarketplace.getListingForDataVault(dataVaultId);
      expect(listingForDataVault).to.equal(0);
    });
    
    it("Should prevent non-owners from modifying listings", async function () {
      const dataVaultId = 1;
      const createTx = await dataMarketplace.connect(dataOwner1).createListing(
        dataVaultId,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        true,
        0,
        CATEGORY_MEDICAL
      );
      const createReceipt = await createTx.wait();
      const createEvent = createReceipt.events.find(event => event.event === "ListingCreated");
      const listingId = createEvent.args.listingId;
      
      await expect(
        dataMarketplace.connect(dataOwner2).updateListing(
          listingId,
          DEFAULT_PRICE,
          LISTING_STATE_ACTIVE,
          true,
          sampleAccessRequirements,
          sampleDataDescription,
          sampleDataTags
        )
      ).to.be.revertedWith("Not the listing owner");
      
      await expect(
        dataMarketplace.connect(dataOwner2).closeListing(listingId)
      ).to.be.revertedWith("Not authorized to close listing");
    });
    
    it("Should prevent listing already listed DataVaults", async function () {
      const dataVaultId = 1;
      await dataMarketplace.connect(dataOwner1).createListing(
        dataVaultId,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        true,
        0,
        CATEGORY_MEDICAL
      );
      
      await expect(
        dataMarketplace.connect(dataOwner1).createListing(
          dataVaultId,
          DEFAULT_PRICE,
          ACCESS_TYPE_SUBSCRIPTION,
          PAYMENT_MODEL_FIXED,
          SUBSCRIPTION_PERIOD,
          sampleAccessRequirements,
          sampleDataDescription,
          sampleDataTags,
          true,
          0,
          CATEGORY_MEDICAL
        )
      ).to.be.revertedWith("DataVault already listed");
    });
  });
  
  // ==========================================================================
  // Access Request and Approval Tests
  // ==========================================================================
  
  describe("Access Request and Approval", function () {
    let listingId;
    
    beforeEach(async function () {
      const dataVaultId = 1;
      const tx = await dataMarketplace.connect(dataOwner1).createListing(
        dataVaultId,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        false,
        0,
        CATEGORY_MEDICAL
      );
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "ListingCreated");
      listingId = event.args.listingId;
    });
    
    it("Should request access to a listing", async function () {
      const purpose = samplePurpose;
      const offeredPrice = DEFAULT_PRICE;
      const tx = await dataMarketplace.connect(researcher1).requestAccess(
        listingId,
        purpose,
        offeredPrice
      );
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "AccessRequested");
      
      expect(event.args.listingId).to.equal(listingId);
      expect(event.args.researcher).to.equal(researcher1.address);
      expect(event.args.purpose).to.equal(purpose);
      expect(event.args.offeredPrice).to.equal(offeredPrice);
      
      const requests = await dataMarketplace.getAccessRequests(listingId);
      expect(requests.length).to.equal(1);
      expect(requests[0].researcher).to.equal(researcher1.address);
      expect(requests[0].purpose).to.equal(purpose);
      expect(requests[0].approved).to.equal(false);
      
      const researcherRequests = await dataMarketplace.getRequestsByResearcher(researcher1.address);
      expect(researcherRequests.length).to.equal(1);
      expect(researcherRequests[0]).to.equal(listingId);
    });
    
    it("Should approve an access request", async function () {
      await dataMarketplace.connect(researcher1).requestAccess(
        listingId,
        samplePurpose,
        DEFAULT_PRICE
      );
      const requestId = 0;
      const agreedPrice = DEFAULT_PRICE;
      
      const initialDataOwnerBalance = await privaToken.balanceOf(dataOwner1.address);
      const initialResearcherBalance = await privaToken.balanceOf(researcher1.address);
      const initialFeeCollectorBalance = await privaToken.balanceOf(feeCollector.address);
      
      const tx = await dataMarketplace.connect(dataOwner1).approveAccess(
        listingId,
        requestId,
        agreedPrice
      );
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "AccessApproved");
      
      expect(event.args.listingId).to.equal(listingId);
      expect(event.args.researcher).to.equal(researcher1.address);
      
      const transactionEvent = receipt.events.find(event => event.event === "TransactionExecuted");
      expect(transactionEvent.args.listingId).to.equal(listingId);
      expect(transactionEvent.args.buyer).to.equal(researcher1.address);
      expect(transactionEvent.args.seller).to.equal(dataOwner1.address);
      expect(transactionEvent.args.price).to.equal(agreedPrice);
      
      expect(await dataMarketplace.hasActiveAccess(researcher1.address, 1)).to.equal(true);
      expect(await dataMarketplace.getAccessExpiration(researcher1.address, 1)).to.be.gt(0);
      
      const finalDataOwnerBalance = await privaToken.balanceOf(dataOwner1.address);
      const finalResearcherBalance = await privaToken.balanceOf(researcher1.address);
      const finalFeeCollectorBalance = await privaToken.balanceOf(feeCollector.address);
      
      const protocolFee = agreedPrice.mul(500).div(10000);
      const sellerAmount = agreedPrice.sub(protocolFee);
      
      expect(finalDataOwnerBalance.sub(initialDataOwnerBalance)).to.equal(sellerAmount);
      expect(initialResearcherBalance.sub(finalResearcherBalance)).to.equal(agreedPrice);
      expect(finalFeeCollectorBalance.sub(initialFeeCollectorBalance)).to.equal(protocolFee);
    });
    
    it("Should deny an access request", async function () {
      await dataMarketplace.connect(researcher1).requestAccess(
        listingId,
        samplePurpose,
        DEFAULT_PRICE
      );
      const requestId = 0;
      const denialReason = "Insufficient research credentials";
      
      const tx = await dataMarketplace.connect(dataOwner1).denyAccess(
        listingId,
        requestId,
        denialReason
      );
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "AccessDenied");
      
      expect(event.args.listingId).to.equal(listingId);
      expect(event.args.researcher).to.equal(researcher1.address);
      expect(event.args.reason).to.equal(denialReason);
      
      const requests = await dataMarketplace.getAccessRequests(listingId);
      expect(requests[0].denialReason).to.equal(denialReason);
    });
    
    it("Should handle direct purchase for fixed-price listings", async function () {
      const dataVaultId = 2;
      const fixedPriceTx = await dataMarketplace.connect(dataOwner1).createListing(
        dataVaultId,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        false,
        0,
        CATEGORY_MEDICAL
      );
      const fixedPriceReceipt = await fixedPriceTx.wait();
      const fixedPriceEvent = fixedPriceReceipt.events.find(event => event.event === "ListingCreated");
      const fixedPriceListingId = fixedPriceEvent.args.listingId;
      
      const initialDataOwnerBalance = await privaToken.balanceOf(dataOwner1.address);
      const initialResearcherBalance = await privaToken.balanceOf(researcher1.address);
      
      const tx = await dataMarketplace.connect(researcher1).directPurchase(fixedPriceListingId);
      const receipt = await tx.wait();
      const transactionEvent = receipt.events.find(event => event.event === "TransactionExecuted");
      
      expect(transactionEvent.args.listingId).to.equal(fixedPriceListingId);
      expect(transactionEvent.args.buyer).to.equal(researcher1.address);
      expect(transactionEvent.args.seller).to.equal(dataOwner1.address);
      
      expect(await dataMarketplace.hasActiveAccess(researcher1.address, dataVaultId)).to.equal(true);
      
      const finalDataOwnerBalance = await privaToken.balanceOf(dataOwner1.address);
      const finalResearcherBalance = await privaToken.balanceOf(researcher1.address);
      
      expect(finalDataOwnerBalance).to.be.gt(initialDataOwnerBalance);
      expect(finalResearcherBalance).to.be.lt(initialResearcherBalance);
    });
    
    it("Should handle per-query payment model", async function () {
      const dataVaultId = 3;
      const perQueryPrice = ethers.utils.parseEther("1");
      const perQueryTx = await dataMarketplace.connect(dataOwner2).createListing(
        dataVaultId,
        perQueryPrice,
        ACCESS_TYPE_SUBSCRIPTION,
        PAYMENT_MODEL_PER_QUERY,
        SUBSCRIPTION_PERIOD,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        false,
        0,
        CATEGORY_FINANCIAL
      );
      const perQueryReceipt = await perQueryTx.wait();
      const perQueryEvent = perQueryReceipt.events.find(event => event.event === "ListingCreated");
      const perQueryListingId = perQueryEvent.args.listingId;
      
      await dataMarketplace.connect(researcher1).requestAccess(perQueryListingId, samplePurpose, 0);
      await dataMarketplace.connect(dataOwner2).approveAccess(perQueryListingId, 0, 0);
      
      const initialDataOwnerBalance = await privaToken.balanceOf(dataOwner2.address);
      const initialResearcherBalance = await privaToken.balanceOf(researcher1.address);
      
      await dataMarketplace.connect(dataOwner2).recordQuery(perQueryListingId, researcher1.address);
      
      const finalDataOwnerBalance = await privaToken.balanceOf(dataOwner2.address);
      const finalResearcherBalance = await privaToken.balanceOf(researcher1.address);
      
      expect(finalDataOwnerBalance).to.be.gt(initialDataOwnerBalance);
      expect(finalResearcherBalance).to.be.lt(initialResearcherBalance);
    });
    
    it("Should block access after expiration", async function () {
      await dataMarketplace.connect(researcher1).requestAccess(listingId, samplePurpose, DEFAULT_PRICE);
      await dataMarketplace.connect(dataOwner1).approveAccess(listingId, 0, DEFAULT_PRICE);
      
      expect(await dataMarketplace.hasActiveAccess(researcher1.address, 1)).to.equal(true);
      await time.increase(ONE_DAY + 1);
      expect(await dataMarketplace.hasActiveAccess(researcher1.address, 1)).to.equal(false);
    });
  });
  
  // ==========================================================================
  // Researcher Verification Tests
  // ==========================================================================
  
  describe("Researcher Verification", function () {
    it("Should submit researcher credentials", async function () {
      await dataMarketplace.connect(researcher1).submitResearcherCredentials(
        sampleOrganization,
        sampleCredentials
      );
      const verification = await dataMarketplace.researcherVerifications(researcher1.address);
      
      expect(verification.researcher).to.equal(researcher1.address);
      expect(verification.organization).to.equal(sampleOrganization);
      expect(verification.credentials).to.equal(sampleCredentials);
      expect(verification.verified).to.equal(false);
    });
    
    it("Should verify a researcher", async function () {
      await dataMarketplace.connect(researcher1).submitResearcherCredentials(
        sampleOrganization,
        sampleCredentials
      );
      const tx = await dataMarketplace.connect(verifier).verifyResearcher(researcher1.address);
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "ResearcherVerified");
      
      expect(event.args.researcher).to.equal(researcher1.address);
      expect(event.args.verifier).to.equal(verifier.address);
      expect(event.args.organization).to.equal(sampleOrganization);
      
      expect(await dataMarketplace.isResearcherVerified(researcher1.address)).to.equal(true);
      
      const history = await dataMarketplace.getVerificationHistory(researcher1.address);
      expect(history.length).to.equal(1);
      expect(history[0]).to.equal(verifier.address);
    });
    
    it("Should revoke researcher verification", async function () {
      await dataMarketplace.connect(researcher1).submitResearcherCredentials(
        sampleOrganization,
        sampleCredentials
      );
      await dataMarketplace.connect(verifier).verifyResearcher(researcher1.address);
      await dataMarketplace.connect(verifier).revokeVerification(researcher1.address);
      
      expect(await dataMarketplace.isResearcherVerified(researcher1.address)).to.equal(false);
    });
    
    it("Should not allow unverified researchers to access listings requiring verification", async function () {
      const dataVaultId = 4;
      const tx = await dataMarketplace.connect(dataOwner1).createListing(
        dataVaultId,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        true,
        0,
        CATEGORY_MEDICAL
      );
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "ListingCreated");
      const listingId = event.args.listingId;
      
      await expect(
        dataMarketplace.connect(researcher1).requestAccess(listingId, samplePurpose, DEFAULT_PRICE)
      ).to.be.revertedWith("Researcher verification required");
      
      await dataMarketplace.connect(researcher1).submitResearcherCredentials(
        sampleOrganization,
        sampleCredentials
      );
      await dataMarketplace.connect(verifier).verifyResearcher(researcher1.address);
      
      await dataMarketplace.connect(researcher1).requestAccess(listingId, samplePurpose, DEFAULT_PRICE);
    });
  });
  
  // ==========================================================================
  // Category and Discovery Tests
  // ==========================================================================
  
  describe("Category and Discovery", function () {
    it("Should add a new category", async function () {
      const newCategory = "Education";
      await dataMarketplace.addCategory(newCategory);
      const categories = await dataMarketplace.getAllCategories();
      expect(categories).to.include(newCategory);
    });
    
    it("Should search listings based on criteria", async function () {
      await dataMarketplace.connect(dataOwner1).createListing(
        1,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        false,
        0,
        CATEGORY_MEDICAL
      );
      await dataMarketplace.connect(dataOwner2).createListing(
        2,
        ethers.utils.parseEther("50"),
        ACCESS_TYPE_SUBSCRIPTION,
        PAYMENT_MODEL_FIXED,
        SUBSCRIPTION_PERIOD,
        sampleAccessRequirements,
        "Financial data",
        ["finance", "investment"],
        false,
        0,
        CATEGORY_FINANCIAL
      );
      
      const medicalListings = await dataMarketplace.searchListings(
        CATEGORY_MEDICAL,
        0,
        0,
        0,
        [],
        false
      );
      expect(medicalListings.length).to.equal(1);
      
      const financialListings = await dataMarketplace.searchListings(
        CATEGORY_FINANCIAL,
        0,
        ethers.utils.parseEther("100"),
        ACCESS_TYPE_SUBSCRIPTION,
        ["finance"],
        false
      );
      expect(financialListings.length).to.equal(1);
    });
    
    it("Should get featured listings", async function () {
      for (let i = 1; i <= 3; i++) {
        await dataMarketplace.connect(dataOwner1).createListing(
          i,
          DEFAULT_PRICE,
          ACCESS_TYPE_ONE_TIME,
          PAYMENT_MODEL_FIXED,
          0,
          sampleAccessRequirements,
          sampleDataDescription,
          sampleDataTags,
          false,
          0,
          CATEGORY_MEDICAL
        );
      }
      const featured = await dataMarketplace.getFeaturedListings(2);
      expect(featured.length).to.equal(2);
    });
    
    it("Should get recommended listings for a researcher", async function () {
      await dataMarketplace.connect(dataOwner1).createListing(
        1,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        false,
        0,
        CATEGORY_MEDICAL
      );
      await dataMarketplace.connect(researcher1).requestAccess(1, samplePurpose, DEFAULT_PRICE);
      
      const recommended = await dataMarketplace.getRecommendedListings(researcher1.address, 1);
      expect(recommended.length).to.equal(1);
    });
  });
  
  // ==========================================================================
  // Fee Management Tests
  // ==========================================================================
  
  describe("Fee Management", function () {
    it("Should have correct initial protocol fee rate", async function () {
      const feeRate = await dataMarketplace.getProtocolFeeRate();
      expect(feeRate).to.equal(500); // 5%
    });
    
    it("Should allow updating protocol fee rate", async function () {
      const newFeeRate = 1000; // 10%
      await dataMarketplace.setProtocolFeeRate(newFeeRate);
      const updatedFeeRate = await dataMarketplace.getProtocolFeeRate();
      expect(updatedFeeRate).to.equal(newFeeRate);
    });
    
    it("Should allow updating fee collector", async function () {
      const initialCollector = await dataMarketplace.getFeeCollector();
      expect(initialCollector).to.equal(feeCollector.address);
      
      await dataMarketplace.setFeeCollector(owner.address);
      const newCollector = await dataMarketplace.getFeeCollector();
      expect(newCollector).to.equal(owner.address);
    });
  });
  
  // ==========================================================================
  // Statistics Tests
  // ==========================================================================
  
  describe("Statistics", function () {
    it("Should track marketplace statistics", async function () {
      await dataMarketplace.connect(dataOwner1).createListing(
        1,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        false,
        0,
        CATEGORY_MEDICAL
      );
      await dataMarketplace.connect(researcher1).directPurchase(1);
      
      const stats = await dataMarketplace.getMarketplaceStats();
      expect(stats.totalListings).to.equal(1);
      expect(stats.activeListings).to.equal(1);
      expect(stats.totalTransactions).to.equal(1);
      expect(stats.totalVolume).to.equal(DEFAULT_PRICE);
      expect(stats.uniqueBuyers).to.equal(1);
      expect(stats.uniqueSellers).to.equal(1);
    });
    
    it("Should track category statistics", async function () {
      await dataMarketplace.connect(dataOwner1).createListing(
        1,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        false,
        0,
        CATEGORY_MEDICAL
      );
      await dataMarketplace.connect(dataOwner2).createListing(
        2,
        ethers.utils.parseEther("50"),
        ACCESS_TYPE_SUBSCRIPTION,
        PAYMENT_MODEL_FIXED,
        SUBSCRIPTION_PERIOD,
        sampleAccessRequirements,
        "Financial data",
        ["finance", "investment"],
        false,
        0,
        CATEGORY_FINANCIAL
      );
      
      const medicalStats = await dataMarketplace.getCategoryStats(CATEGORY_MEDICAL);
      expect(medicalStats.listingCount).to.equal(1);
      expect(medicalStats.transactionCount).to.equal(0);
      expect(medicalStats.volume).to.equal(0);
      expect(medicalStats.averagePrice).to.equal(DEFAULT_PRICE);
      
      const financialStats = await dataMarketplace.getCategoryStats(CATEGORY_FINANCIAL);
      expect(financialStats.listingCount).to.equal(1);
      expect(financialStats.averagePrice).to.equal(ethers.utils.parseEther("50"));
    });
  });
  
  // ==========================================================================
  // Admin Functions Tests
  // ==========================================================================
  
  describe("Admin Functions", function () {
    it("Should allow pausing and unpausing the marketplace", async function () {
      expect(await dataMarketplace.isPaused()).to.equal(false);
      await dataMarketplace.pause();
      expect(await dataMarketplace.isPaused()).to.equal(true);
      
      await expect(
        dataMarketplace.connect(dataOwner1).createListing(
          1,
          DEFAULT_PRICE,
          ACCESS_TYPE_ONE_TIME,
          PAYMENT_MODEL_FIXED,
          0,
          sampleAccessRequirements,
          sampleDataDescription,
          sampleDataTags,
          false,
          0,
          CATEGORY_MEDICAL
        )
      ).to.be.revertedWith("Marketplace is paused");
      
      await dataMarketplace.unpause();
      expect(await dataMarketplace.isPaused()).to.equal(false);
      
      await dataMarketplace.connect(dataOwner1).createListing(
        1,
        DEFAULT_PRICE,
        ACCESS_TYPE_ONE_TIME,
        PAYMENT_MODEL_FIXED,
        0,
        sampleAccessRequirements,
        sampleDataDescription,
        sampleDataTags,
        false,
        0,
        CATEGORY_MEDICAL
      );
    });
    
    it("Should enforce role-based access for admin functions", async function () {
      await expect(
        dataMarketplace.connect(dataOwner1).pause()
      ).to.be.revertedWith("Not authorized");
      
      const ADMIN_ROLE = await dataMarketplace.ADMIN_ROLE();
      await dataMarketplace.grantRole(ADMIN_ROLE, dataOwner1.address);
      
      await dataMarketplace.connect(dataOwner1).pause();
      expect(await dataMarketplace.isPaused()).to.equal(true);
    });
  });
});
