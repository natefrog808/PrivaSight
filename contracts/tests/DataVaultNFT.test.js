const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("DataVaultNFT", function () {
  // Contract instances
  let dataVaultNFT;
  let privaToken;
  
  // Mock addresses and variables
  let owner;
  let researcher1;
  let researcher2;
  let contributor;
  let feeCollector;
  let treasury;
  
  // Constants for testing
  const ZERO_ADDRESS = ethers.constants.AddressZero;
  const TOKEN_DECIMALS = 18;
  const TOKEN_SUPPLY = ethers.utils.parseEther("1000000"); // 1 million tokens
  const STAKE_AMOUNT = ethers.utils.parseEther("100"); // 100 tokens
  const COMPENSATION = ethers.utils.parseEther("10"); // 10 tokens
  
  // Sample data for tests
  const sampleDataHash = "QmSampleHashForEncryptedDataOnIPFS123456789";
  const sampleEncryptionKeyHash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
  const sampleAccessRules = '{"allowedPurposes": ["medical_research"], "allowedOrganizations": ["Research Institute"]}';
  const sampleDataCategory = "medical";
  const sampleMetadataURI = "ipfs://QmSampleMetadataURI";
  
  // Sample request data
  const requestPurpose = "Diabetes research study";
  
  beforeEach(async function () {
    // Get signers for different test roles
    [owner, researcher1, researcher2, contributor, feeCollector, treasury] = await ethers.getSigners();
    
    // Deploy PRIVA token
    const PrivaToken = await ethers.getContractFactory("PrivaToken");
    privaToken = await PrivaToken.deploy(TOKEN_SUPPLY, feeCollector.address);
    await privaToken.deployed();
    
    // Deploy DataVaultNFT
    const DataVaultNFT = await ethers.getContractFactory("DataVaultNFT");
    dataVaultNFT = await DataVaultNFT.deploy(privaToken.address);
    await dataVaultNFT.deployed();
    
    // Approve tokens for staking to the DataVaultNFT contract
    await privaToken.connect(owner).approve(dataVaultNFT.address, STAKE_AMOUNT);
    
    // Transfer some tokens to researchers for testing
    await privaToken.transfer(researcher1.address, STAKE_AMOUNT);
    await privaToken.transfer(researcher2.address, STAKE_AMOUNT);
    await privaToken.connect(researcher1).approve(dataVaultNFT.address, STAKE_AMOUNT);
    await privaToken.connect(researcher2).approve(dataVaultNFT.address, STAKE_AMOUNT);
  });
  
  // ==========================================================================
  // Minting and Basic Functionality Tests
  // ==========================================================================
  
  describe("Minting and basic functionality", function () {
    it("Should mint a new DataVault NFT", async function () {
      const initialBalance = await dataVaultNFT.balanceOf(owner.address);
      
      // Mint a DataVault
      const tx = await dataVaultNFT.mintDataVault(
        sampleDataHash,
        sampleEncryptionKeyHash,
        sampleAccessRules,
        sampleDataCategory,
        sampleMetadataURI,
        0 // No staking initially
      );
      
      // Wait for transaction to be mined
      const receipt = await tx.wait();
      
      // Find tokenId from the event
      const event = receipt.events.find(event => event.event === "DataVaultMinted");
      const tokenId = event.args.tokenId;
      
      // Verify minting was successful
      expect(await dataVaultNFT.balanceOf(owner.address)).to.equal(initialBalance.add(1));
      expect(await dataVaultNFT.ownerOf(tokenId)).to.equal(owner.address);
      
      // Check DataVault data
      const vaultInfo = await dataVaultNFT.getDataVaultInfo(tokenId);
      expect(vaultInfo.dataHash).to.equal(sampleDataHash);
      expect(vaultInfo.accessRules).to.equal(sampleAccessRules);
      expect(vaultInfo.dataCategory).to.equal(sampleDataCategory);
      expect(vaultInfo.stakingAmount).to.equal(0);
    });
    
    it("Should mint a DataVault NFT with staking", async function () {
      // Mint a DataVault with staking
      const tx = await dataVaultNFT.mintDataVault(
        sampleDataHash,
        sampleEncryptionKeyHash,
        sampleAccessRules,
        sampleDataCategory,
        sampleMetadataURI,
        STAKE_AMOUNT
      );
      
      // Wait for transaction to be mined
      const receipt = await tx.wait();
      
      // Find tokenId from the event
      const event = receipt.events.find(event => event.event === "DataVaultMinted");
      const tokenId = event.args.tokenId;
      
      // Check DataVault data includes stake
      const vaultInfo = await dataVaultNFT.getDataVaultInfo(tokenId);
      expect(vaultInfo.stakingAmount).to.equal(STAKE_AMOUNT);
      
      // Verify tokens were transferred
      expect(await privaToken.balanceOf(dataVaultNFT.address)).to.equal(STAKE_AMOUNT);
    });
    
    it("Should update access rules", async function () {
      // Mint a DataVault
      const tx = await dataVaultNFT.mintDataVault(
        sampleDataHash,
        sampleEncryptionKeyHash,
        sampleAccessRules,
        sampleDataCategory,
        sampleMetadataURI,
        0
      );
      
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "DataVaultMinted");
      const tokenId = event.args.tokenId;
      
      // New access rules
      const newAccessRules = '{"allowedPurposes": ["cardiology_research"], "allowedOrganizations": ["University"]}';
      
      // Update access rules
      await dataVaultNFT.updateAccessRules(tokenId, newAccessRules);
      
      // Verify update
      const vaultInfo = await dataVaultNFT.getDataVaultInfo(tokenId);
      expect(vaultInfo.accessRules).to.equal(newAccessRules);
    });
    
    it("Should update data hash when data is updated", async function () {
      // Mint a DataVault
      const tx = await dataVaultNFT.mintDataVault(
        sampleDataHash,
        sampleEncryptionKeyHash,
        sampleAccessRules,
        sampleDataCategory,
        sampleMetadataURI,
        0
      );
      
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "DataVaultMinted");
      const tokenId = event.args.tokenId;
      
      // New data hash and encryption key hash
      const newDataHash = "QmNewHashForUpdatedEncryptedDataOnIPFS";
      const newEncryptionKeyHash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
      
      // Update data hash
      await dataVaultNFT.updateDataHash(tokenId, newDataHash, newEncryptionKeyHash);
      
      // Verify update
      const vaultInfo = await dataVaultNFT.getDataVaultInfo(tokenId);
      expect(vaultInfo.dataHash).to.equal(newDataHash);
    });
    
    it("Should add more stake to an existing DataVault", async function () {
      // Mint a DataVault with initial stake
      const initialStake = STAKE_AMOUNT.div(2);
      const tx = await dataVaultNFT.mintDataVault(
        sampleDataHash,
        sampleEncryptionKeyHash,
        sampleAccessRules,
        sampleDataCategory,
        sampleMetadataURI,
        initialStake
      );
      
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "DataVaultMinted");
      const tokenId = event.args.tokenId;
      
      // Additional stake
      const additionalStake = STAKE_AMOUNT.div(2);
      
      // Add more stake
      await dataVaultNFT.addStake(tokenId, additionalStake);
      
      // Verify stake was added
      const vaultInfo = await dataVaultNFT.getDataVaultInfo(tokenId);
      expect(vaultInfo.stakingAmount).to.equal(initialStake.add(additionalStake));
    });
    
    it("Should revert operations when called by non-owners", async function () {
      // Mint a DataVault
      const tx = await dataVaultNFT.mintDataVault(
        sampleDataHash,
        sampleEncryptionKeyHash,
        sampleAccessRules,
        sampleDataCategory,
        sampleMetadataURI,
        0
      );
      
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "DataVaultMinted");
      const tokenId = event.args.tokenId;
      
      // Try to update as non-owner
      await expect(
        dataVaultNFT.connect(researcher1).updateAccessRules(tokenId, "new rules")
      ).to.be.revertedWith("Not authorized to modify rules");
      
      await expect(
        dataVaultNFT.connect(researcher1).updateDataHash(tokenId, "new hash", "new key hash")
      ).to.be.revertedWith("Not authorized to update data");
      
      await expect(
        dataVaultNFT.connect(researcher1).addStake(tokenId, STAKE_AMOUNT)
      ).to.be.revertedWith("Only owner can stake");
    });
  });
  
  // ==========================================================================
  // Access Control Tests
  // ==========================================================================
  
  describe("Access Control", function () {
    let tokenId;
    
    beforeEach(async function () {
      // Mint a DataVault for access control tests
      const tx = await dataVaultNFT.mintDataVault(
        sampleDataHash,
        sampleEncryptionKeyHash,
        sampleAccessRules,
        sampleDataCategory,
        sampleMetadataURI,
        0
      );
      
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "DataVaultMinted");
      tokenId = event.args.tokenId;
    });
    
    it("Should allow researchers to request access", async function () {
      // Request access as researcher
      const tx = await dataVaultNFT.connect(researcher1).requestAccess(
        tokenId,
        requestPurpose,
        COMPENSATION
      );
      
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "AccessRequested");
      
      // Verify request was created
      expect(event.args.tokenId).to.equal(tokenId);
      expect(event.args.requester).to.equal(researcher1.address);
      expect(event.args.purpose).to.equal(requestPurpose);
      
      // Get request details
      const requests = await dataVaultNFT.getAccessRequests(tokenId);
      expect(requests.length).to.equal(1);
      expect(requests[0].requester).to.equal(researcher1.address);
      expect(requests[0].purpose).to.equal(requestPurpose);
      expect(requests[0].compensation).to.equal(COMPENSATION);
      expect(requests[0].approved).to.equal(false);
    });
    
    it("Should allow owner to approve access requests", async function () {
      // Request access as researcher
      const requestTx = await dataVaultNFT.connect(researcher1).requestAccess(
        tokenId,
        requestPurpose,
        COMPENSATION
      );
      
      // Request ID is 0 (first request)
      const requestId = 0;
      
      // Duration of access (1 day)
      const durationSeconds = 86400;
      
      // Approve access
      const approveTx = await dataVaultNFT.approveAccess(
        tokenId,
        requestId,
        durationSeconds
      );
      
      const receipt = await approveTx.wait();
      const event = receipt.events.find(event => event.event === "AccessGranted");
      
      // Verify approval
      expect(event.args.tokenId).to.equal(tokenId);
      expect(event.args.requester).to.equal(researcher1.address);
      
      // Check access status
      expect(await dataVaultNFT.hasAccess(tokenId, researcher1.address)).to.equal(true);
      
      // Check expiration
      const expiration = await dataVaultNFT.getAccessExpiration(tokenId, researcher1.address);
      expect(expiration).to.be.gt(0);
    });
    
    it("Should allow owner to revoke access", async function () {
      // Request and approve access
      await dataVaultNFT.connect(researcher1).requestAccess(tokenId, requestPurpose, COMPENSATION);
      await dataVaultNFT.approveAccess(tokenId, 0, 86400);
      
      // Verify access is granted
      expect(await dataVaultNFT.hasAccess(tokenId, researcher1.address)).to.equal(true);
      
      // Revoke access
      await dataVaultNFT.revokeAccess(tokenId, researcher1.address);
      
      // Verify access is revoked
      expect(await dataVaultNFT.hasAccess(tokenId, researcher1.address)).to.equal(false);
    });
    
    it("Should respect access expiration", async function () {
      // Request and approve access with short duration (10 seconds)
      await dataVaultNFT.connect(researcher1).requestAccess(tokenId, requestPurpose, COMPENSATION);
      await dataVaultNFT.approveAccess(tokenId, 0, 10);
      
      // Verify access is granted
      expect(await dataVaultNFT.hasAccess(tokenId, researcher1.address)).to.equal(true);
      
      // Fast forward time by 15 seconds
      await time.increase(15);
      
      // Verify access has expired
      expect(await dataVaultNFT.hasAccess(tokenId, researcher1.address)).to.equal(false);
    });
    
    it("Should not allow non-owners to approve or revoke access", async function () {
      // Request access
      await dataVaultNFT.connect(researcher1).requestAccess(tokenId, requestPurpose, COMPENSATION);
      
      // Try to approve as non-owner
      await expect(
        dataVaultNFT.connect(researcher2).approveAccess(tokenId, 0, 86400)
      ).to.be.revertedWith("Not authorized to grant access");
      
      // Owner approves access
      await dataVaultNFT.approveAccess(tokenId, 0, 86400);
      
      // Try to revoke as non-owner
      await expect(
        dataVaultNFT.connect(researcher2).revokeAccess(tokenId, researcher1.address)
      ).to.be.revertedWith("Not authorized to revoke access");
    });
  });
  
  // ==========================================================================
  // Research and Computation Tests
  // ==========================================================================
  
  describe("Research and Computation", function () {
    let tokenId;
    let requestId;
    
    beforeEach(async function () {
      // Mint a DataVault
      const tx = await dataVaultNFT.mintDataVault(
        sampleDataHash,
        sampleEncryptionKeyHash,
        sampleAccessRules,
        sampleDataCategory,
        sampleMetadataURI,
        0
      );
      
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "DataVaultMinted");
      tokenId = event.args.tokenId;
      
      // Set up approved access for research tests
      await dataVaultNFT.connect(researcher1).requestAccess(tokenId, requestPurpose, COMPENSATION);
      requestId = 0; // First request has ID 0
      await dataVaultNFT.approveAccess(tokenId, requestId, 86400);
      
      // Ensure researcher has tokens for compensation
      await privaToken.transfer(researcher1.address, COMPENSATION);
      await privaToken.connect(researcher1).approve(dataVaultNFT.address, COMPENSATION);
    });
    
    it("Should allow researcher to publish results", async function () {
      // Result hash
      const resultHash = "QmResultHashForComputationResults123456789";
      
      // Publish results
      const tx = await dataVaultNFT.connect(researcher1).publishResults(
        tokenId,
        requestId,
        resultHash
      );
      
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "ResultsPublished");
      
      // Verify results published
      expect(event.args.tokenId).to.equal(tokenId);
      expect(event.args.researcher).to.equal(researcher1.address);
      expect(event.args.resultHash).to.equal(resultHash);
      
      // Check usage statistics updated
      const stats = await dataVaultNFT.getUsageStatistics(tokenId);
      expect(stats.timesAccessed).to.equal(1);
      expect(stats.tokensEarned).to.equal(COMPENSATION);
    });
    
    it("Should revert publication if researcher doesn't have access", async function () {
      // Try to publish as unapproved researcher
      await expect(
        dataVaultNFT.connect(researcher2).publishResults(tokenId, requestId, "result hash")
      ).to.be.revertedWith("Only requester can publish results");
    });
    
    it("Should revert publication if request not approved", async function () {
      // Create another request that hasn't been approved
      await dataVaultNFT.connect(researcher2).requestAccess(tokenId, "Different purpose", COMPENSATION);
      const unapprovedRequestId = 1; // Second request
      
      // Try to publish with unapproved request
      await expect(
        dataVaultNFT.connect(researcher2).publishResults(tokenId, unapprovedRequestId, "result hash")
      ).to.be.revertedWith("Access not approved");
    });
    
    it("Should record usage properly", async function () {
      // Record usage (usually called by trusted components)
      await dataVaultNFT.connect(owner).recordUsage(
        tokenId,
        researcher1.address,
        "query"
      );
      
      // Check usage statistics
      const stats = await dataVaultNFT.getUsageStatistics(tokenId);
      expect(stats.timesAccessed).to.equal(1);
      
      // Record another usage
      await dataVaultNFT.connect(owner).recordUsage(
        tokenId,
        researcher1.address,
        "download"
      );
      
      // Check usage statistics updated
      const updatedStats = await dataVaultNFT.getUsageStatistics(tokenId);
      expect(updatedStats.timesAccessed).to.equal(2);
    });
    
    it("Should handle compensation correctly when results are published", async function () {
      // Check initial balances
      const initialOwnerBalance = await privaToken.balanceOf(owner.address);
      const initialResearcherBalance = await privaToken.balanceOf(researcher1.address);
      
      // Publish results with compensation
      await dataVaultNFT.connect(researcher1).publishResults(
        tokenId,
        requestId,
        "result hash"
      );
      
      // Check final balances
      const finalOwnerBalance = await privaToken.balanceOf(owner.address);
      const finalResearcherBalance = await privaToken.balanceOf(researcher1.address);
      
      // Verify compensation was paid
      expect(finalOwnerBalance).to.equal(initialOwnerBalance.add(COMPENSATION));
      expect(finalResearcherBalance).to.equal(initialResearcherBalance.sub(COMPENSATION));
    });
  });
  
  // ==========================================================================
  // Revenue and Token Tests
  // ==========================================================================
  
  describe("Revenue and Tokens", function () {
    let tokenId;
    
    beforeEach(async function () {
      // Mint a DataVault with staking
      const tx = await dataVaultNFT.mintDataVault(
        sampleDataHash,
        sampleEncryptionKeyHash,
        sampleAccessRules,
        sampleDataCategory,
        sampleMetadataURI,
        STAKE_AMOUNT
      );
      
      const receipt = await tx.wait();
      const event = receipt.events.find(event => event.event === "DataVaultMinted");
      tokenId = event.args.tokenId;
    });
    
    it("Should track staked balance correctly", async function () {
      const stakedBalance = await dataVaultNFT.getStakedBalance(tokenId);
      expect(stakedBalance).to.equal(STAKE_AMOUNT);
    });
    
    it("Should return correct staker address", async function () {
      const staker = await dataVaultNFT.getStaker(tokenId);
      expect(staker).to.equal(owner.address);
    });
    
    it("Should calculate revenue shares correctly", async function () {
      const totalAmount = ethers.utils.parseEther("100");
      
      // Get revenue shares
      const [ownerShare, stakerShare, platformShare] = await dataVaultNFT.calculateRevenueShares(
        tokenId,
        totalAmount
      );
      
      // Verify shares sum to total amount
      expect(ownerShare.add(stakerShare).add(platformShare)).to.equal(totalAmount);
      
      // Check shares are in expected ranges
      expect(ownerShare).to.be.gt(totalAmount.div(2)); // Owner gets majority
      expect(stakerShare).to.be.gt(0); // Staker gets a share
      expect(platformShare).to.be.gt(0); // Platform gets a share
    });
    
    it("Should allow withdrawing staking rewards", async function () {
      // Simulate rewards by transferring tokens
      const rewardAmount = ethers.utils.parseEther("5");
      await privaToken.transfer(dataVaultNFT.address, rewardAmount);
      
      // Record the reward
      await dataVaultNFT.connect(owner).recordStakingReward(tokenId, rewardAmount);
      
      // Check initial balance
      const initialBalance = await privaToken.balanceOf(owner.address);
      
      // Withdraw rewards
      await dataVaultNFT.withdrawStakingRewards(tokenId);
      
      // Check final balance
      const finalBalance = await privaToken.balanceOf(owner.address);
      expect(finalBalance).to.be.gt(initialBalance);
    });
    
    it("Should handle revenue distribution correctly", async function () {
      // Simulate revenue
      const revenue = ethers.utils.parseEther("50");
      
      // Grant DISTRIBUTOR_ROLE to owner
      const DISTRIBUTOR_ROLE = await dataVaultNFT.DISTRIBUTOR_ROLE();
      await dataVaultNFT.grantRole(DISTRIBUTOR_ROLE, owner.address);
      
      // Transfer tokens to contract
      await privaToken.transfer(dataVaultNFT.address, revenue);
      
      // Check initial balances
      const initialOwnerBalance = await privaToken.balanceOf(owner.address);
      const initialTreasuryBalance = await privaToken.balanceOf(treasury.address);
      
      // Distribute revenue
      await dataVaultNFT.distributeRevenue(tokenId, revenue, treasury.address);
      
      // Check final balances
      const finalOwnerBalance = await privaToken.balanceOf(owner.address);
      const finalTreasuryBalance = await privaToken.balanceOf(treasury.address);
      
      expect(finalOwnerBalance).to.be.gt(initialOwnerBalance);
      expect(finalTreasuryBalance).to.be.gt(initialTreasuryBalance);
    });
  });
  
  // ==========================================================================
  // Compliance and Management Tests
  // ==========================================================================
  
  describe("Compliance and Management", function () {
    beforeEach(async function () {
      // Create multiple DataVaults
      for (let i = 0; i < 3; i++) {
        await dataVaultNFT.mintDataVault(
          `${sampleDataHash}-${i}`,
          sampleEncryptionKeyHash,
          sampleAccessRules,
          sampleDataCategory,
          sampleMetadataURI,
          0
        );
      }
      
      // Mint a vault in a different category
      await dataVaultNFT.mintDataVault(
        `${sampleDataHash}-different`,
        sampleEncryptionKeyHash,
        sampleAccessRules,
        "financial",
        sampleMetadataURI,
        0
      );
    });
    
    it("Should track DataVaults by owner", async function () {
      const ownerVaults = await dataVaultNFT.getDataVaultsByOwner(owner.address);
      expect(ownerVaults.length).to.equal(4); // 3 medical + 1 financial
    });
    
    it("Should track DataVaults by category", async function () {
      const medicalVaults = await dataVaultNFT.getDataVaultsByCategory(sampleDataCategory);
      const financialVaults = await dataVaultNFT.getDataVaultsByCategory("financial");
      
      expect(medicalVaults.length).to.equal(3);
      expect(financialVaults.length).to.equal(1);
    });
    
    it("Should handle verification correctly", async function () {
      const tokenId = 1; // First minted vault
      
      expect(await dataVaultNFT.isVerified(tokenId)).to.equal(false);
      
      // Grant VERIFIER_ROLE
      const VERIFIER_ROLE = await dataVaultNFT.VERIFIER_ROLE();
      await dataVaultNFT.grantRole(VERIFIER_ROLE, contributor.address);
      
      // Verify DataVault
      await dataVaultNFT.connect(contributor).verifyDataVault(tokenId);
      
      expect(await dataVaultNFT.isVerified(tokenId)).to.equal(true);
      
      const verificationDetails = await dataVaultNFT.getVerificationDetails(tokenId);
      expect(verificationDetails.verified).to.equal(true);
      expect(verificationDetails.verifier).to.equal(contributor.address);
    });
    
    it("Should not allow non-verifiers to verify DataVaults", async function () {
      await expect(
        dataVaultNFT.connect(researcher1).verifyDataVault(1)
      ).to.be.revertedWith("Caller is not a verifier");
    });
  });
  
  // ==========================================================================
  // Integration Tests
  // ==========================================================================
  
  describe("Integration scenarios", function () {
    it("Should handle full lifecycle of DataVault with research", async function () {
      // 1. Mint DataVault with staking
      const mintTx = await dataVaultNFT.mintDataVault(
        sampleDataHash,
        sampleEncryptionKeyHash,
        sampleAccessRules,
        sampleDataCategory,
        sampleMetadataURI,
        STAKE_AMOUNT.div(2)
      );
      const mintReceipt = await mintTx.wait();
      const tokenId = mintReceipt.events.find(event => event.event === "DataVaultMinted").args.tokenId;
      
      // 2. Add more stake
      await dataVaultNFT.addStake(tokenId, STAKE_AMOUNT.div(2));
      
      // 3. Researcher requests access
      await privaToken.transfer(researcher1.address, COMPENSATION.mul(2));
      await privaToken.connect(researcher1).approve(dataVaultNFT.address, COMPENSATION.mul(2));
      await dataVaultNFT.connect(researcher1).requestAccess(tokenId, requestPurpose, COMPENSATION);
      
      // 4. Owner approves access
      await dataVaultNFT.approveAccess(tokenId, 0, 86400);
      
      // 5. Researcher publishes results
      await dataVaultNFT.connect(researcher1).publishResults(tokenId, 0, "result hash 1");
      
      // 6. Verify usage statistics
      let stats = await dataVaultNFT.getUsageStatistics(tokenId);
      expect(stats.timesAccessed).to.equal(1);
      expect(stats.tokensEarned).to.equal(COMPENSATION);
      
      // 7. Researcher requests again with higher compensation
      await dataVaultNFT.connect(researcher1).requestAccess(tokenId, "Follow-up research", COMPENSATION.mul(2));
      
      // 8. Owner approves again
      await dataVaultNFT.approveAccess(tokenId, 1, 86400);
      
      // 9. Researcher publishes more results
      await dataVaultNFT.connect(researcher1).publishResults(tokenId, 1, "result hash 2");
      
      // 10. Check final statistics
      stats = await dataVaultNFT.getUsageStatistics(tokenId);
      expect(stats.timesAccessed).to.equal(2);
      expect(stats.tokensEarned).to.equal(COMPENSATION.add(COMPENSATION.mul(2)));
    });
  });
});
