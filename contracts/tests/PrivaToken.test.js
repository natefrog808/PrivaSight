const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("PrivaToken", function () {
  // Contract instance
  let privaToken;
  
  // Mock addresses and variables
  let owner;
  let user1;
  let user2;
  let user3;
  let feeCollector;
  let treasury;
  let communityFund;
  
  // Constants for testing
  const ZERO_ADDRESS = ethers.constants.AddressZero;
  const PERCENTAGE_BASE = 10000; // 100% = 10000 basis points
  
  // Token constants
  const TOKEN_DECIMALS = 18;
  const INITIAL_SUPPLY = ethers.utils.parseEther("100000000"); // 100 million tokens
  const MAX_SUPPLY = ethers.utils.parseEther("1000000000"); // 1 billion tokens
  
  // Staking constants
  const MIN_STAKE_AMOUNT = ethers.utils.parseEther("100"); // 100 tokens
  const STAKE_AMOUNT = ethers.utils.parseEther("1000"); // 1000 tokens
  const LARGE_STAKE_AMOUNT = ethers.utils.parseEther("10000"); // 10000 tokens
  const MIN_STAKE_DURATION = 60 * 60 * 24 * 7; // 7 days
  const STAKE_DURATION = 60 * 60 * 24 * 30; // 30 days
  
  // Fee constants
  const DEFAULT_FEE_RATE = 100; // 1%
  const NEW_FEE_RATE = 200; // 2%
  
  beforeEach(async function () {
    // Get signers for different test roles
    [owner, user1, user2, user3, feeCollector, treasury, communityFund] = await ethers.getSigners();
    
    // Deploy PRIVA token
    const PrivaToken = await ethers.getContractFactory("PrivaToken");
    privaToken = await PrivaToken.deploy(INITIAL_SUPPLY, feeCollector.address);
    await privaToken.deployed();
    
    // Transfer tokens to test accounts
    await privaToken.transfer(user1.address, STAKE_AMOUNT.mul(5));
    await privaToken.transfer(user2.address, STAKE_AMOUNT.mul(5));
    await privaToken.transfer(user3.address, STAKE_AMOUNT.mul(5));
  });
  
  // ==========================================================================
  // Basic Token Tests
  // ==========================================================================
  
  describe("Basic token functionality", function () {
    it("Should have correct name, symbol, and decimals", async function () {
      expect(await privaToken.name()).to.equal("PrivaSight Token");
      expect(await privaToken.symbol()).to.equal("PRIVA");
      expect(await privaToken.decimals()).to.equal(18);
    });
    
    it("Should have correct initial supply", async function () {
      const totalSupply = await privaToken.totalSupply();
      expect(totalSupply).to.equal(INITIAL_SUPPLY);
      
      const circulatingSupply = await privaToken.getCirculatingSupply();
      expect(circulatingSupply).to.equal(INITIAL_SUPPLY);
      
      const ownerBalance = await privaToken.balanceOf(owner.address);
      expect(ownerBalance).to.be.gt(0);
    });
    
    it("Should have correct max supply", async function () {
      const maxSupply = await privaToken.getMaxSupply();
      expect(maxSupply).to.equal(MAX_SUPPLY);
    });
    
    it("Should allow basic transfers", async function () {
      const transferAmount = ethers.utils.parseEther("100");
      const initialUser3Balance = await privaToken.balanceOf(user3.address);
      
      await privaToken.transfer(user3.address, transferAmount);
      
      const finalUser3Balance = await privaToken.balanceOf(user3.address);
      expect(finalUser3Balance.sub(initialUser3Balance)).to.equal(transferAmount);
    });
    
    it("Should deduct fees on transfers", async function () {
      const transferAmount = ethers.utils.parseEther("1000");
      const initialFeeCollectorBalance = await privaToken.balanceOf(feeCollector.address);
      const initialUser2Balance = await privaToken.balanceOf(user2.address);
      
      await privaToken.connect(user1).transfer(user2.address, transferAmount);
      
      const feeCollectorBalance = await privaToken.balanceOf(feeCollector.address);
      const expectedFee = transferAmount.mul(DEFAULT_FEE_RATE).div(PERCENTAGE_BASE);
      expect(feeCollectorBalance.sub(initialFeeCollectorBalance)).to.equal(expectedFee);
      
      const finalUser2Balance = await privaToken.balanceOf(user2.address);
      const user2ReceivedAmount = transferAmount.sub(expectedFee);
      expect(finalUser2Balance.sub(initialUser2Balance)).to.equal(user2ReceivedAmount);
    });
    
    it("Should allow owner to mint new tokens", async function () {
      const mintAmount = ethers.utils.parseEther("1000000");
      const initialSupply = await privaToken.totalSupply();
      const initialTreasuryBalance = await privaToken.balanceOf(treasury.address);
      
      await privaToken.mint(treasury.address, mintAmount);
      
      const newSupply = await privaToken.totalSupply();
      expect(newSupply).to.equal(initialSupply.add(mintAmount));
      
      const treasuryBalance = await privaToken.balanceOf(treasury.address);
      expect(treasuryBalance.sub(initialTreasuryBalance)).to.equal(mintAmount);
    });
    
    it("Should not allow minting beyond max supply", async function () {
      const currentSupply = await privaToken.totalSupply();
      const remainingSupply = MAX_SUPPLY.sub(currentSupply);
      const exceedingAmount = remainingSupply.add(ethers.utils.parseEther("1"));
      
      await expect(
        privaToken.mint(treasury.address, exceedingAmount)
      ).to.be.revertedWith("Max supply exceeded");
    });
    
    it("Should allow pausing and unpausing", async function () {
      expect(await privaToken.paused()).to.equal(false);
      
      await privaToken.pause();
      expect(await privaToken.paused()).to.equal(true);
      
      await expect(
        privaToken.transfer(user1.address, ethers.utils.parseEther("100"))
      ).to.be.revertedWith("ERC20Pausable: token transfer while paused");
      
      await privaToken.unpause();
      expect(await privaToken.paused()).to.equal(false);
      
      const initialUser1Balance = await privaToken.balanceOf(user1.address);
      await privaToken.transfer(user1.address, ethers.utils.parseEther("100"));
      const finalUser1Balance = await privaToken.balanceOf(user1.address);
      expect(finalUser1Balance.sub(initialUser1Balance)).to.equal(ethers.utils.parseEther("100"));
    });
  });
  
  // ==========================================================================
  // Fee Management Tests
  // ==========================================================================
  
  describe("Fee management", function () {
    it("Should have correct initial fee rate", async function () {
      const feeRate = await privaToken.getTransactionFeeRate();
      expect(feeRate).to.equal(DEFAULT_FEE_RATE);
    });
    
    it("Should allow updating fee rate", async function () {
      await privaToken.setTransactionFeeRate(NEW_FEE_RATE);
      const feeRate = await privaToken.getTransactionFeeRate();
      expect(feeRate).to.equal(NEW_FEE_RATE);
    });
    
    it("Should not allow setting fee rate above maximum", async function () {
      const MAX_FEE_RATE = await privaToken.MAX_FEE_RATE();
      await expect(
        privaToken.setTransactionFeeRate(MAX_FEE_RATE.add(1))
      ).to.be.revertedWith("Fee rate exceeds maximum");
    });
    
    it("Should allow updating fee collector", async function () {
      const initialCollector = await privaToken.getFeeCollector();
      expect(initialCollector).to.equal(feeCollector.address);
      
      await privaToken.setFeeCollector(treasury.address);
      const newCollector = await privaToken.getFeeCollector();
      expect(newCollector).to.equal(treasury.address);
    });
    
    it("Should apply correct fee discount based on staking tier", async function () {
      let applicableFeeRate = await privaToken.getApplicableFeeRate(user1.address);
      expect(applicableFeeRate).to.equal(DEFAULT_FEE_RATE);
      
      await privaToken.connect(user1).approve(privaToken.address, LARGE_STAKE_AMOUNT);
      await privaToken.connect(user1).stake(LARGE_STAKE_AMOUNT, STAKE_DURATION);
      
      applicableFeeRate = await privaToken.getApplicableFeeRate(user1.address);
      expect(applicableFeeRate).to.be.lt(DEFAULT_FEE_RATE);
    });
  });
  
  // ==========================================================================
  // Staking Tests
  // ==========================================================================
  
  describe("Staking", function () {
    it("Should allow staking tokens", async function () {
      await privaToken.connect(user1).approve(privaToken.address, STAKE_AMOUNT);
      const initialContractBalance = await privaToken.balanceOf(privaToken.address);
      
      const tx = await privaToken.connect(user1).stake(STAKE_AMOUNT, STAKE_DURATION);
      const receipt = await tx.wait();
      const stakeEvent = receipt.events.find(e => e.event === "Staked");
      const stakeId = stakeEvent.args.stakeId;
      
      const stakeDetails = await privaToken.getStakeDetails(user1.address, stakeId);
      expect(stakeDetails.amount).to.equal(STAKE_AMOUNT);
      expect(stakeDetails.active).to.equal(true);
      
      const contractBalance = await privaToken.balanceOf(privaToken.address);
      expect(contractBalance.sub(initialContractBalance)).to.equal(STAKE_AMOUNT);
    });
    
    it("Should not allow staking below minimum amount", async function () {
      const belowMinimum = MIN_STAKE_AMOUNT.sub(1);
      await privaToken.connect(user1).approve(privaToken.address, belowMinimum);
      
      await expect(
        privaToken.connect(user1).stake(belowMinimum, STAKE_DURATION)
      ).to.be.revertedWith("Amount below minimum stake");
    });
    
    it("Should not allow staking below minimum duration", async function () {
      await privaToken.connect(user1).approve(privaToken.address, STAKE_AMOUNT);
      const belowMinDuration = MIN_STAKE_DURATION - 1;
      
      await expect(
        privaToken.connect(user1).stake(STAKE_AMOUNT, belowMinDuration)
      ).to.be.revertedWith("Duration below minimum");
    });
    
    it("Should allow unstaking after duration completes", async function () {
      await privaToken.connect(user1).approve(privaToken.address, STAKE_AMOUNT);
      const tx = await privaToken.connect(user1).stake(STAKE_AMOUNT, STAKE_DURATION);
      const receipt = await tx.wait();
      const stakeEvent = receipt.events.find(e => e.event === "Staked");
      const stakeId = stakeEvent.args.stakeId;
      
      await time.increase(STAKE_DURATION + 1);
      const initialBalance = await privaToken.balanceOf(user1.address);
      
      await privaToken.connect(user1).unstake(stakeId);
      
      const finalBalance = await privaToken.balanceOf(user1.address);
      expect(finalBalance.sub(initialBalance)).to.equal(STAKE_AMOUNT);
      
      const stakeDetails = await privaToken.getStakeDetails(user1.address, stakeId);
      expect(stakeDetails.active).to.equal(false);
    });
    
    it("Should apply penalty when unstaking early", async function () {
      await privaToken.connect(user1).approve(privaToken.address, STAKE_AMOUNT);
      const tx = await privaToken.connect(user1).stake(STAKE_AMOUNT, STAKE_DURATION);
      const receipt = await tx.wait();
      const stakeEvent = receipt.events.find(e => e.event === "Staked");
      const stakeId = stakeEvent.args.stakeId;
      
      const initialBalance = await privaToken.balanceOf(user1.address);
      await privaToken.connect(user1).unstake(stakeId);
      
      const finalBalance = await privaToken.balanceOf(user1.address);
      const UNSTAKE_PENALTY_RATE = await privaToken.UNSTAKE_PENALTY_RATE();
      const expectedPenalty = STAKE_AMOUNT.mul(UNSTAKE_PENALTY_RATE).div(PERCENTAGE_BASE);
      const expectedReturn = STAKE_AMOUNT.sub(expectedPenalty);
      
      expect(finalBalance.sub(initialBalance)).to.equal(expectedReturn);
    });
    
    it("Should allow staking on DataVault NFT", async function () {
      await privaToken.connect(user1).approve(privaToken.address, STAKE_AMOUNT);
      const stakeTx = await privaToken.connect(user1).stake(STAKE_AMOUNT, STAKE_DURATION);
      const stakeReceipt = await stakeTx.wait();
      const stakeEvent = stakeReceipt.events.find(e => e.event === "Staked");
      const stakeId = stakeEvent.args.stakeId;
      
      const dataVaultId = 1;
      const dvStakeTx = await privaToken.connect(user1).stakeOnDataVault(dataVaultId, stakeId);
      const dvStakeReceipt = await dvStakeTx.wait();
      const dvStakeEvent = dvStakeReceipt.events.find(e => e.event === "DataVaultStaked");
      
      expect(dvStakeEvent.args.staker).to.equal(user1.address);
      expect(dvStakeEvent.args.dataVaultId).to.equal(dataVaultId);
      expect(dvStakeEvent.args.stakeId).to.equal(stakeId);
      
      const staker = await privaToken.getDataVaultStaker(dataVaultId);
      expect(staker).to.equal(user1.address);
    });
    
    it("Should allow unstaking from DataVault NFT", async function () {
      await privaToken.connect(user1).approve(privaToken.address, STAKE_AMOUNT);
      const stakeTx = await privaToken.connect(user1).stake(STAKE_AMOUNT, STAKE_DURATION);
      const stakeReceipt = await stakeTx.wait();
      const stakeEvent = stakeReceipt.events.find(e => e.event === "Staked");
      const stakeId = stakeEvent.args.stakeId;
      
      const dataVaultId = 1;
      await privaToken.connect(user1).stakeOnDataVault(dataVaultId, stakeId);
      const dvStakeId = 0; // First DataVault stake
      
      await privaToken.connect(user1).unstakeFromDataVault(dvStakeId);
      const staker = await privaToken.getDataVaultStaker(dataVaultId);
      expect(staker).to.equal(ZERO_ADDRESS);
    });
  });
  
  // ==========================================================================
  // Staking Tier Tests
  // ==========================================================================
  
  describe("Staking tiers", function () {
    it("Should have correct initial tiers", async function () {
      const tiers = await privaToken.getStakingTiers();
      expect(tiers.length).to.be.gte(4);
      
      for (let i = 1; i < tiers.length; i++) {
        expect(tiers[i].minAmount).to.be.gt(tiers[i - 1].minAmount);
      }
    });
    
    it("Should calculate correct tier based on stake amount", async function () {
      let [tierIndex, tier] = await privaToken.getStakingTier(user1.address);
      expect(tierIndex).to.equal(0);
      
      await privaToken.connect(user1).approve(privaToken.address, LARGE_STAKE_AMOUNT);
      await privaToken.connect(user1).stake(LARGE_STAKE_AMOUNT, STAKE_DURATION);
      
      [tierIndex, tier] = await privaToken.getStakingTier(user1.address);
      expect(tierIndex).to.be.gt(0);
    });
    
    it("Should allow adding new staking tier", async function () {
      const initialTierCount = (await privaToken.getStakingTiers()).length;
      const newTierMinAmount = ethers.utils.parseEther("500000");
      const rewardMultiplier = 250;
      const feeDiscount = 50;
      const marketplaceAccess = true;
      const governanceAccess = true;
      const priorityAccess = true;
      
      await privaToken.addStakingTier(
        newTierMinAmount,
        rewardMultiplier,
        feeDiscount,
        marketplaceAccess,
        governanceAccess,
        priorityAccess
      );
      
      const tiers = await privaToken.getStakingTiers();
      expect(tiers.length).to.equal(initialTierCount + 1);
      
      const newTier = tiers[tiers.length - 1];
      expect(newTier.minAmount).to.equal(newTierMinAmount);
      expect(newTier.rewardMultiplier).to.equal(rewardMultiplier);
      expect(newTier.feeDiscount).to.equal(feeDiscount);
    });
    
    it("Should allow updating existing tier", async function () {
      const tierIndex = 0;
      const updatedMinAmount = ethers.utils.parseEther("150");
      const updatedMultiplier = 110;
      const updatedFeeDiscount = 10;
      const updatedMarketplaceAccess = true;
      const updatedGovernanceAccess = false;
      const updatedPriorityAccess = false;
      
      await privaToken.updateStakingTier(
        tierIndex,
        updatedMinAmount,
        updatedMultiplier,
        updatedFeeDiscount,
        updatedMarketplaceAccess,
        updatedGovernanceAccess,
        updatedPriorityAccess
      );
      
      const [, tier] = await privaToken.getStakingTier(ZERO_ADDRESS);
      expect(tier.minAmount).to.equal(updatedMinAmount);
      expect(tier.rewardMultiplier).to.equal(updatedMultiplier);
      expect(tier.feeDiscount).to.equal(updatedFeeDiscount);
      expect(tier.marketplaceAccess).to.equal(updatedMarketplaceAccess);
      expect(tier.governanceAccess).to.equal(updatedGovernanceAccess);
      expect(tier.priorityAccess).to.equal(updatedPriorityAccess);
    });
  });
  
  // ==========================================================================
  // Reward Tests
  // ==========================================================================
  
  describe("Rewards", function () {
    it("Should allow distributing rewards", async function () {
      const rewardAmount = ethers.utils.parseEther("100");
      const reason = "Contribution to research";
      
      const REWARD_DISTRIBUTOR_ROLE = await privaToken.REWARD_DISTRIBUTOR_ROLE();
      await privaToken.grantRole(REWARD_DISTRIBUTOR_ROLE, owner.address);
      
      await privaToken.distributeReward(user1.address, rewardAmount, reason);
      const unclaimedRewards = await privaToken.getUnclaimedRewards(user1.address);
      expect(unclaimedRewards).to.equal(rewardAmount);
    });
    
    it("Should apply reward multiplier based on staking tier", async function () {
      await privaToken.connect(user1).approve(privaToken.address, LARGE_STAKE_AMOUNT);
      await privaToken.connect(user1).stake(LARGE_STAKE_AMOUNT, STAKE_DURATION);
      
      const [, tier] = await privaToken.getStakingTier(user1.address);
      const multiplier = tier.rewardMultiplier;
      
      const REWARD_DISTRIBUTOR_ROLE = await privaToken.REWARD_DISTRIBUTOR_ROLE();
      await privaToken.grantRole(REWARD_DISTRIBUTOR_ROLE, owner.address);
      
      const baseRewardAmount = ethers.utils.parseEther("100");
      await privaToken.distributeReward(user1.address, baseRewardAmount, "Research reward");
      
      const expectedReward = baseRewardAmount.mul(multiplier).div(100);
      const unclaimedRewards = await privaToken.getUnclaimedRewards(user1.address);
      expect(unclaimedRewards).to.equal(expectedReward);
    });
    
    it("Should allow claiming rewards", async function () {
      const rewardAmount = ethers.utils.parseEther("100");
      const REWARD_DISTRIBUTOR_ROLE = await privaToken.REWARD_DISTRIBUTOR_ROLE();
      await privaToken.grantRole(REWARD_DISTRIBUTOR_ROLE, owner.address);
      await privaToken.distributeReward(user1.address, rewardAmount, "Research reward");
      
      const initialBalance = await privaToken.balanceOf(user1.address);
      await privaToken.connect(user1).claimRewards();
      const finalBalance = await privaToken.balanceOf(user1.address);
      
      expect(finalBalance.sub(initialBalance)).to.equal(rewardAmount);
      const unclaimedRewards = await privaToken.getUnclaimedRewards(user1.address);
      expect(unclaimedRewards).to.equal(0);
    });
    
    it("Should revert when claiming with no rewards", async function () {
      await expect(
        privaToken.connect(user2).claimRewards()
      ).to.be.revertedWith("No rewards to claim");
    });
  });
  
  // ==========================================================================
  // Governance Access Tests
  // ==========================================================================
  
  describe("Governance access", function () {
    it("Should grant governance access based on staking tier", async function () {
      expect(await privaToken.hasGovernanceAccess(user1.address)).to.equal(false);
      
      await privaToken.connect(user1).approve(privaToken.address, LARGE_STAKE_AMOUNT);
      await privaToken.connect(user1).stake(LARGE_STAKE_AMOUNT, STAKE_DURATION);
      
      const [, tier] = await privaToken.getStakingTier(user1.address);
      if (tier.governanceAccess) {
        expect(await privaToken.hasGovernanceAccess(user1.address)).to.equal(true);
      }
    });
    
    it("Should grant marketplace access based on staking tier", async function () {
      const initialHasAccess = await privaToken.hasMarketplaceAccess(user1.address);
      
      await privaToken.connect(user1).approve(privaToken.address, LARGE_STAKE_AMOUNT);
      await privaToken.connect(user1).stake(LARGE_STAKE_AMOUNT, STAKE_DURATION);
      
      const [, tier] = await privaToken.getStakingTier(user1.address);
      if (tier.marketplaceAccess) {
        expect(await privaToken.hasMarketplaceAccess(user1.address)).to.equal(true);
      } else {
        expect(await privaToken.hasMarketplaceAccess(user1.address)).to.equal(initialHasAccess);
      }
    });
    
    it("Should grant priority access based on staking tier", async function () {
      expect(await privaToken.hasPriorityAccess(user1.address)).to.equal(false);
      
      await privaToken.connect(user1).approve(privaToken.address, LARGE_STAKE_AMOUNT);
      await privaToken.connect(user1).stake(LARGE_STAKE_AMOUNT, STAKE_DURATION);
      
      const [, tier] = await privaToken.getStakingTier(user1.address);
      if (tier.priorityAccess) {
        expect(await privaToken.hasPriorityAccess(user1.address)).to.equal(true);
      }
    });
    
    it("Should allow role-based governance access", async function () {
      const GOVERNANCE_ROLE = await privaToken.GOVERNANCE_ROLE();
      await privaToken.grantRole(GOVERNANCE_ROLE, user3.address);
      expect(await privaToken.hasGovernanceAccess(user3.address)).to.equal(true);
    });
  });
  
  // ==========================================================================
  // Integration Tests
  // ==========================================================================
  
  describe("Integration scenarios", function () {
    it("Should handle complete staking, unstaking, and rewards flow", async function () {
      await privaToken.connect(user1).approve(privaToken.address, STAKE_AMOUNT);
      const stakeTx = await privaToken.connect(user1).stake(STAKE_AMOUNT, STAKE_DURATION);
      const stakeReceipt = await stakeTx.wait();
      const stakeEvent = stakeReceipt.events.find(e => e.event === "Staked");
      const stakeId = stakeEvent.args.stakeId;
      
      const [tierIndex, tier] = await privaToken.getStakingTier(user1.address);
      expect(tierIndex).to.be.gte(0);
      
      const REWARD_DISTRIBUTOR_ROLE = await privaToken.REWARD_DISTRIBUTOR_ROLE();
      await privaToken.grantRole(REWARD_DISTRIBUTOR_ROLE, owner.address);
      const baseRewardAmount = ethers.utils.parseEther("50");
      await privaToken.distributeReward(user1.address, baseRewardAmount, "Research contribution");
      
      const expectedReward = baseRewardAmount.mul(tier.rewardMultiplier).div(100);
      const unclaimedRewards = await privaToken.getUnclaimedRewards(user1.address);
      expect(unclaimedRewards).to.equal(expectedReward);
      
      const initialBalanceAfterStake = await privaToken.balanceOf(user1.address);
      await privaToken.connect(user1).claimRewards();
      const balanceAfterClaim = await privaToken.balanceOf(user1.address);
      expect(balanceAfterClaim.sub(initialBalanceAfterStake)).to.equal(expectedReward);
      
      await time.increase(STAKE_DURATION + 1);
      await privaToken.connect(user1).unstake(stakeId);
      const finalBalance = await privaToken.balanceOf(user1.address);
      expect(finalBalance.sub(balanceAfterClaim)).to.equal(STAKE_AMOUNT);
      
      const [finalTierIndex] = await privaToken.getStakingTier(user1.address);
      expect(finalTierIndex).to.equal(0);
    });
    
    it("Should handle DataVault staking and unstaking flow", async function () {
      await privaToken.connect(user1).approve(privaToken.address, STAKE_AMOUNT);
      const stakeTx = await privaToken.connect(user1).stake(STAKE_AMOUNT, STAKE_DURATION);
      const stakeReceipt = await stakeTx.wait();
      const stakeEvent = stakeReceipt.events.find(e => e.event === "Staked");
      const stakeId = stakeEvent.args.stakeId;
      
      const dataVaultId1 = 1;
      const dataVaultId2 = 2;
      await privaToken.connect(user1).stakeOnDataVault(dataVaultId1, stakeId);
      expect(await privaToken.getDataVaultStaker(dataVaultId1)).to.equal(user1.address);
      
      await privaToken.connect(user2).approve(privaToken.address, STAKE_AMOUNT);
      const user2StakeTx = await privaToken.connect(user2).stake(STAKE_AMOUNT, STAKE_DURATION);
      const user2StakeReceipt = await user2StakeTx.wait();
      const user2StakeEvent = user2StakeReceipt.events.find(e => e.event === "Staked");
      const user2StakeId = user2StakeEvent.args.stakeId;
      
      await expect(
        privaToken.connect(user2).stakeOnDataVault(dataVaultId1, user2StakeId)
      ).to.be.revertedWith("DataVault already has staker");
      
      await privaToken.connect(user2).stakeOnDataVault(dataVaultId2, user2StakeId);
      expect(await privaToken.getDataVaultStaker(dataVaultId2)).to.equal(user2.address);
      
      const dvStakeId = 0;
      await privaToken.connect(user1).unstakeFromDataVault(dvStakeId);
      expect(await privaToken.getDataVaultStaker(dataVaultId1)).to.equal(ZERO_ADDRESS);
      
      await privaToken.connect(user2).stakeOnDataVault(dataVaultId1, user2StakeId);
      expect(await privaToken.getDataVaultStaker(dataVaultId1)).to.equal(user2.address);
    });
    
    it("Should handle transfer fees and discounts correctly", async function () {
      const transferAmount = ethers.utils.parseEther("1000");
      const initialFeeCollectorBalance = await privaToken.balanceOf(feeCollector.address);
      await privaToken.connect(user1).transfer(user2.address, transferAmount);
      
      const feeCollectorBalance1 = await privaToken.balanceOf(feeCollector.address);
      const fee1 = feeCollectorBalance1.sub(initialFeeCollectorBalance);
      const expectedFee1 = transferAmount.mul(DEFAULT_FEE_RATE).div(PERCENTAGE_BASE);
      expect(fee1).to.equal(expectedFee1);
      
      await privaToken.connect(user1).approve(privaToken.address, LARGE_STAKE_AMOUNT);
      await privaToken.connect(user1).stake(LARGE_STAKE_AMOUNT, STAKE_DURATION);
      
      const discountedFeeRate = await privaToken.getApplicableFeeRate(user1.address);
      await privaToken.connect(user1).transfer(user2.address, transferAmount);
      
      const feeCollectorBalance2 = await privaToken.balanceOf(feeCollector.address);
      const fee2 = feeCollectorBalance2.sub(feeCollectorBalance1);
      const expectedFee2 = transferAmount.mul(discountedFeeRate).div(PERCENTAGE_BASE);
      const feeDifference = expectedFee2.sub(fee2).abs();
      expect(feeDifference).to.be.lte(ethers.utils.parseEther("0.000001"));
    });
  });
  
  // ==========================================================================
  // Role-Based Access Control Tests
  // ==========================================================================
  
  describe("Role-based access control", function () {
    it("Should enforce role-based permissions", async function () {
      const MINTER_ROLE = await privaToken.MINTER_ROLE();
      const PAUSER_ROLE = await privaToken.PAUSER_ROLE();
      const REWARD_DISTRIBUTOR_ROLE = await privaToken.REWARD_DISTRIBUTOR_ROLE();
      const GOVERNANCE_ROLE = await privaToken.GOVERNANCE_ROLE();
      
      await expect(
        privaToken.connect(user1).mint(user1.address, ethers.utils.parseEther("1000"))
      ).to.be.revertedWith(/AccessControl/);
      
      await expect(
        privaToken.connect(user1).pause()
      ).to.be.revertedWith(/AccessControl/);
      
      await expect(
        privaToken.connect(user1).distributeReward(user2.address, ethers.utils.parseEther("100"), "Test")
      ).to.be.revertedWith(/AccessControl/);
      
      await expect(
        privaToken.connect(user1).setTransactionFeeRate(NEW_FEE_RATE)
      ).to.be.revertedWith(/AccessControl/);
      
      await privaToken.grantRole(MINTER_ROLE, user3.address);
      await privaToken.grantRole(PAUSER_ROLE, user3.address);
      await privaToken.grantRole(REWARD_DISTRIBUTOR_ROLE, user3.address);
      await privaToken.grantRole(GOVERNANCE_ROLE, user3.address);
      
      const initialUser3Balance = await privaToken.balanceOf(user3.address);
      await privaToken.connect(user3).mint(user3.address, ethers.utils.parseEther("1000"));
      expect((await privaToken.balanceOf(user3.address)).sub(initialUser3Balance)).to.equal(ethers.utils.parseEther("1000"));
      
      await privaToken.connect(user3).pause();
      expect(await privaToken.paused()).to.equal(true);
      await privaToken.connect(user3).unpause();
      
      await privaToken.connect(user3).distributeReward(user1.address, ethers.utils.parseEther("100"), "Test");
      expect(await privaToken.getUnclaimedRewards(user1.address)).to.equal(ethers.utils.parseEther("100"));
      
      await privaToken.connect(user3).setTransactionFeeRate(NEW_FEE_RATE);
      expect(await privaToken.getTransactionFeeRate()).to.equal(NEW_FEE_RATE);
    });
    
    it("Should allow revoking roles", async function () {
      const MINTER_ROLE = await privaToken.MINTER_ROLE();
      await privaToken.grantRole(MINTER_ROLE, user3.address);
      expect(await privaToken.hasRole(MINTER_ROLE, user3.address)).to.equal(true);
      
      const initialBalance = await privaToken.balanceOf(user3.address);
      await privaToken.connect(user3).mint(user3.address, ethers.utils.parseEther("1000"));
      expect((await privaToken.balanceOf(user3.address)).sub(initialBalance)).to.equal(ethers.utils.parseEther("1000"));
      
      await privaToken.revokeRole(MINTER_ROLE, user3.address);
      expect(await privaToken.hasRole(MINTER_ROLE, user3.address)).to.equal(false);
      
      await expect(
        privaToken.connect(user3).mint(user3.address, ethers.utils.parseEther("1000"))
      ).to.be.revertedWith(/AccessControl/);
    });
  });
  
  // ==========================================================================
  // Supply Cap and Burn Tests
  // ==========================================================================
  
  describe("Supply cap and burning", function () {
    it("Should enforce max supply cap", async function () {
      const currentSupply = await privaToken.totalSupply();
      const maxSupply = await privaToken.getMaxSupply();
      const mintableAmount = maxSupply.sub(currentSupply);
      
      await privaToken.mint(treasury.address, mintableAmount);
      expect(await privaToken.totalSupply()).to.equal(maxSupply);
      
      await expect(
        privaToken.mint(treasury.address, 1)
      ).to.be.revertedWith("Max supply exceeded");
    });
    
    it("Should allow burning tokens", async function () {
      const burnAmount = ethers.utils.parseEther("1000");
      const initialSupply = await privaToken.totalSupply();
      const initialCirculating = await privaToken.getCirculatingSupply();
      
      await privaToken.burn(burnAmount);
      
      const finalSupply = await privaToken.totalSupply();
      const finalCirculating = await privaToken.getCirculatingSupply();
      expect(initialSupply.sub(finalSupply)).to.equal(burnAmount);
      expect(initialCirculating.sub(finalCirculating)).to.equal(burnAmount);
    });
    
    it("Should auto-burn early unstaking penalties", async function () {
      const initialSupply = await privaToken.totalSupply();
      
      await privaToken.connect(user1).approve(privaToken.address, STAKE_AMOUNT);
      const stakeTx = await privaToken.connect(user1).stake(STAKE_AMOUNT, STAKE_DURATION);
      const stakeReceipt = await stakeTx.wait();
      const stakeEvent = stakeReceipt.events.find(e => e.event === "Staked");
      const stakeId = stakeEvent.args.stakeId;
      
      const unstakeTx = await privaToken.connect(user1).unstake(stakeId);
      const unstakeReceipt = await unstakeTx.wait();
      const unstakeEvent = unstakeReceipt.events.find(e => e.event === "Unstaked");
      const penalized = unstakeEvent.args.penalized;
      const returnedAmount = unstakeEvent.args.amount;
      
      const UNSTAKE_PENALTY_RATE = await privaToken.UNSTAKE_PENALTY_RATE();
      const penalty = STAKE_AMOUNT.mul(UNSTAKE_PENALTY_RATE).div(PERCENTAGE_BASE);
      
      expect(penalized).to.equal(true);
      expect(STAKE_AMOUNT.sub(returnedAmount)).to.equal(penalty);
      
      const finalSupply = await privaToken.totalSupply();
      expect(initialSupply.sub(finalSupply)).to.equal(penalty);
    });
  });
  
  // ==========================================================================
  // ERC20 Extensions Tests
  // ==========================================================================
  
  describe("ERC20 extensions", function () {
    it("Should support permit function", async function () {
      // Basic check for function existence; full permit testing requires signature generation
      expect(typeof privaToken.permit).to.equal("function");
    });
    
    it("Should support voting and delegation", async function () {
      expect(typeof privaToken.delegate).to.equal("function");
      expect(typeof privaToken.delegates).to.equal("function");
      expect(typeof privaToken.getVotes).to.equal("function");
      
      await privaToken.connect(user1).delegate(user1.address);
      const votes = await privaToken.getVotes(user1.address);
      const balance = await privaToken.balanceOf(user1.address);
      expect(votes).to.equal(balance);
    });
  });
});
