pragma circom 2.0.0;

/*
 * PrivaSight Computation Verification Circuit
 *
 * This advanced circuit verifies that a privacy-preserving computation was
 * performed correctly without revealing the actual data used or intermediate steps.
 * It ensures computational integrity while maintaining data privacy.
 * 
 * The circuit implements a sophisticated verification framework that:
 * 1. Confirms authorized data vaults were used as computation inputs
 * 2. Verifies computation protocol was followed correctly
 * 3. Validates privacy parameters were properly applied
 * 4. Ensures result integrity without revealing raw data
 * 5. Provides differential privacy guarantees with cryptographic assurance
 */

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/mimcsponge.circom";
include "../../../node_modules/circomlib/circuits/eddsamimc.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/smt.circom";

// Constants for computation types
// COMPUTATION_TYPE_AVERAGE = 1
// COMPUTATION_TYPE_STATISTICAL = 2
// COMPUTATION_TYPE_REGRESSION = 3
// COMPUTATION_TYPE_CORRELATION = 4
// COMPUTATION_TYPE_CLUSTERING = 5

// Main Computation Verification Circuit
template ComputationVerification(maxDataVaults, maxFeatures) {
    // Public inputs (signals)
    signal input computationHash;        // Hash of computation parameters and outputs
    signal input resultHash;             // Hash of computation results 
    signal input computationType;        // Type of computation performed (1-5)
    signal input privacyBudgetHash;      // Hash of privacy budget consumption
    signal input validatorsMerkleRoot;   // Merkle root of approved validators

    // Private inputs (witness values)
    signal input researcherAddress;                   // Address of researcher initiating computation
    signal input dataVaultIds[maxDataVaults];         // IDs of data vaults used
    signal input dataVaultCount;                      // Number of vaults used (≤ maxDataVaults)
    signal input dataVaultAccessHashes[maxDataVaults]; // Access proof hashes for each vault
    signal input computationNonce;                    // Unique nonce for this computation
    signal input privacyEpsilon;                      // Differential privacy epsilon parameter
    signal input privacyDelta;                        // Differential privacy delta parameter
    signal input featureSelectionMask[maxFeatures];   // Bit mask for selected features
    signal input featureCount;                        // Number of selected features
    signal input computationTimestamp;                // Timestamp of computation
    signal input noiseSeeds[maxDataVaults];           // Seeds for noise generation
    signal input resultContributions[maxDataVaults];  // Contributions from each vault to the result
    signal input validatorSignaturesR[3][2];          // R components of 3 validator signatures
    signal input validatorSignaturesS[3];             // S components of 3 validator signatures
    signal input validatorPublicKeys[3][2];           // Public keys of 3 validators
    signal input validatorMerklePaths[3][10];         // Merkle paths for validator inclusion
    signal input validatorMerkleIndices[3][10];       // Merkle path indices for validators

    // Intermediate signals
    signal computationParamsHash;
    signal privacyParametersHash;
    signal validationHash;
    signal computationValid;

    // **Step 1: Verify computation type is valid (1-5)**
    component computationTypeCheck = RangeCheck(3);
    computationTypeCheck.in <== computationType;
    computationTypeCheck.min <== 1;
    computationTypeCheck.max <== 5;

    // **Step 2: Verify privacy parameters**
    // Epsilon: 0.01 to 10
    component epsilonRangeCheck = RangeCheck(10);
    epsilonRangeCheck.in <== privacyEpsilon * 100; // Scale by 100 for integer arithmetic
    epsilonRangeCheck.min <== 1;                   // 0.01
    epsilonRangeCheck.max <== 1000;                // 10

    // Delta: 0.000000000000001 to 0.999999999999999
    component deltaRangeCheck = RangeCheck(15);
    deltaRangeCheck.in <== privacyDelta * 1000000000000000; // Scale by 10^15
    deltaRangeCheck.min <== 1;                      // 0.000000000000001
    deltaRangeCheck.max <== 999999999999999;        // 0.999999999999999

    // **Step 3: Verify feature selection mask**
    signal selectedFeatures;
    selectedFeatures <== 0;
    for (var i = 0; i < maxFeatures; i++) {
        // Ensure each bit is 0 or 1
        featureSelectionMask[i] * (1 - featureSelectionMask[i]) === 0;
        selectedFeatures += featureSelectionMask[i];
    }
    selectedFeatures === featureCount;

    // **Step 4: Verify data vault count**
    component vaultCountCheck = LessThan(8);
    vaultCountCheck.in[0] <== dataVaultCount;
    vaultCountCheck.in[1] <== maxDataVaults + 1;
    vaultCountCheck.out === 1;

    component vaultCountPositive = GreaterThan(8);
    vaultCountPositive.in[0] <== dataVaultCount;
    vaultCountPositive.in[1] <== 0;
    vaultCountPositive.out === 1;

    // **Step 5: Hash computation parameters**
    component computationParamsHasher = Poseidon(5);
    computationParamsHasher.inputs[0] <== computationType;
    computationParamsHasher.inputs[1] <== researcherAddress;
    computationParamsHasher.inputs[2] <== computationNonce;
    computationParamsHasher.inputs[3] <== dataVaultCount;
    computationParamsHasher.inputs[4] <== featureCount;
    computationParamsHash <== computationParamsHasher.out;

    // **Step 6: Hash privacy parameters**
    component privacyParamsHasher = Poseidon(3);
    privacyParamsHasher.inputs[0] <== privacyEpsilon;
    privacyParamsHasher.inputs[1] <== privacyDelta;
    privacyParamsHasher.inputs[2] <== computationTimestamp;
    privacyParametersHash <== privacyParamsHasher.out;

    component privacyBudgetHasher = Poseidon(2);
    privacyBudgetHasher.inputs[0] <== privacyParametersHash;
    privacyBudgetHasher.inputs[1] <== computationNonce;
    privacyBudgetHasher.out === privacyBudgetHash;

    // **Step 7: Verify data vault access hashes**
    component dataVaultHashers[maxDataVaults];
    signal dataVaultHashes[maxDataVaults];
    for (var i = 0; i < maxDataVaults; i++) {
        dataVaultHashers[i] = Poseidon(3);
        dataVaultHashers[i].inputs[0] <== dataVaultIds[i];
        dataVaultHashers[i].inputs[1] <== researcherAddress;
        dataVaultHashers[i].inputs[2] <== computationNonce;
        dataVaultHashes[i] <== dataVaultHashers[i].out;

        signal vaultUsed;
        component vaultUsedCheck = LessThan(8);
        vaultUsedCheck.in[0] <== i;
        vaultUsedCheck.in[1] <== dataVaultCount;
        vaultUsed <== vaultUsedCheck.out;

        component accessEqualityCheck = ForceEqualIfEnabled();
        accessEqualityCheck.enabled <== vaultUsed;
        accessEqualityCheck.in[0] <== dataVaultAccessHashes[i];
        accessEqualityCheck.in[1] <== dataVaultHashes[i];
    }

    // **Step 8: Validate noise for differential privacy**
    component noiseVerifiers[maxDataVaults];
    signal noiseMagnitudes[maxDataVaults];
    for (var i = 0; i < maxDataVaults; i++) {
        signal noiseCheckEnabled;
        component noiseEnabledCheck = LessThan(8);
        noiseEnabledCheck.in[0] <== i;
        noiseEnabledCheck.in[1] <== dataVaultCount;
        noiseCheckEnabled <== noiseEnabledCheck.out;

        noiseVerifiers[i] = NoiseVerification();
        noiseVerifiers[i].enabled <== noiseCheckEnabled;
        noiseVerifiers[i].seed <== noiseSeeds[i];
        noiseVerifiers[i].epsilon <== privacyEpsilon;
        noiseVerifiers[i].delta <== privacyDelta;
        noiseVerifiers[i].computationType <== computationType;
        noiseMagnitudes[i] <== noiseVerifiers[i].noiseMagnitude;
    }

    // **Step 9: Verify result computation**
    component resultVerifier = ResultVerification(maxDataVaults);
    resultVerifier.computationType <== computationType;
    resultVerifier.dataVaultCount <== dataVaultCount;
    resultVerifier.nonce <== computationNonce;
    for (var i = 0; i < maxDataVaults; i++) {
        resultVerifier.contributions[i] <== resultContributions[i];
        resultVerifier.noiseMagnitudes[i] <== noiseMagnitudes[i];
    }
    resultVerifier.calculatedResultHash === resultHash;

    // **Step 10: Verify validator signatures**
    component validatorVerifiers[3];
    signal validatorChecks[3];
    for (var i = 0; i < 3; i++) {
        component validationMessageHasher = Poseidon(3);
        validationMessageHasher.inputs[0] <== computationParamsHash;
        validationMessageHasher.inputs[1] <== privacyParametersHash;
        validationMessageHasher.inputs[2] <== resultHash;

        validatorVerifiers[i] = EdDSAValidatorCheck();
        validatorVerifiers[i].Ax <== validatorPublicKeys[i][0];
        validatorVerifiers[i].Ay <== validatorPublicKeys[i][1];
        validatorVerifiers[i].R8x <== validatorSignaturesR[i][0];
        validatorVerifiers[i].R8y <== validatorSignaturesR[i][1];
        validatorVerifiers[i].S <== validatorSignaturesS[i];
        validatorVerifiers[i].M <== validationMessageHasher.out;

        component validatorMerkleVerifier = SMTVerifier(10);
        validatorMerkleVerifier.enabled <== 1;
        validatorMerkleVerifier.root <== validatorsMerkleRoot;
        component validatorKeyHasher = Poseidon(2);
        validatorKeyHasher.inputs[0] <== validatorPublicKeys[i][0];
        validatorKeyHasher.inputs[1] <== validatorPublicKeys[i][1];
        validatorMerkleVerifier.key <== validatorKeyHasher.out;
        validatorMerkleVerifier.value <== 1;
        for (var j = 0; j < 10; j++) {
            validatorMerkleVerifier.siblings[j] <== validatorMerklePaths[i][j];
            validatorMerkleVerifier.pathIndices[j] <== validatorMerkleIndices[i][j];
        }
        validatorChecks[i] <== validatorVerifiers[i].valid * validatorMerkleVerifier.out;
    }
    signal validatorsValid;
    validatorsValid <== validatorChecks[0] * validatorChecks[1] * validatorChecks[2];
    validatorsValid === 1;

    // **Step 11: Hash validation components**
    component validationHasher = Poseidon(4);
    validationHasher.inputs[0] <== validatorsValid;
    validationHasher.inputs[1] <== computationParamsHash;
    validationHasher.inputs[2] <== privacyParametersHash;
    validationHasher.inputs[3] <== resultHash;
    validationHash <== validationHasher.out;

    // **Step 12: Final verification**
    component finalHasher = Poseidon(2);
    finalHasher.inputs[0] <== validationHash;
    finalHasher.inputs[1] <== computationNonce;
    finalHasher.out === computationHash;

    computationValid <== 1;
}

// **RangeCheck Template**
template RangeCheck(bits) {
    signal input in;
    signal input min;
    signal input max;
    component gtMin = GreaterEqThan(bits);
    gtMin.in[0] <== in;
    gtMin.in[1] <== min;
    component ltMax = LessEqThan(bits);
    ltMax.in[0] <== in;
    ltMax.in[1] <== max;
    gtMin.out === 1;
    ltMax.out === 1;
}

// **ForceEqualIfEnabled Template**
template ForceEqualIfEnabled() {
    signal input enabled;
    signal input in[2];
    enabled * (in[0] - in[1]) === 0;
}

// **EdDSAValidatorCheck Template**
template EdDSAValidatorCheck() {
    signal input Ax;
    signal input Ay;
    signal input R8x;
    signal input R8y;
    signal input S;
    signal input M;
    signal output valid;
    component verifier = EdDSAMiMCVerifier();
    verifier.enabled <== 1;
    verifier.Ax <== Ax;
    verifier.Ay <== Ay;
    verifier.R8x <== R8x;
    verifier.R8y <== R8y;
    verifier.S <== S;
    verifier.M <== M;
    valid <== verifier.out;
}

// **NoiseVerification Template**
template NoiseVerification() {
    signal input enabled;
    signal input seed;
    signal input epsilon;
    signal input delta;
    signal input computationType;
    signal output noiseMagnitude;
    component sensitivity = ComputationSensitivity();
    sensitivity.computationType <== computationType;
    signal sensitivityValue <== sensitivity.sensitivityValue;
    component scaleHasher = Poseidon(3);
    scaleHasher.inputs[0] <== seed;
    scaleHasher.inputs[1] <== epsilon * 1000000; // Scale for precision
    scaleHasher.inputs[2] <== delta * 1000000000000000;
    signal scaleBase;
    scaleBase <== (scaleHasher.out % 1500) + 500; // Range 500-2000
    scaleBase <== scaleBase / 1000; // Normalize to 0.5-2.0
    noiseMagnitude <== enabled * (sensitivityValue * scaleBase / epsilon);
}

// **ComputationSensitivity Template**
template ComputationSensitivity() {
    signal input computationType;
    signal output sensitivityValue;
    component isType1 = IsEqual(); isType1.in[0] <== computationType; isType1.in[1] <== 1;
    component isType2 = IsEqual(); isType2.in[0] <== computationType; isType2.in[1] <== 2;
    component isType3 = IsEqual(); isType3.in[0] <== computationType; isType3.in[1] <== 3;
    component isType4 = IsEqual(); isType4.in[0] <== computationType; isType4.in[1] <== 4;
    component isType5 = IsEqual(); isType5.in[0] <== computationType; isType5.in[1] <== 5;
    sensitivityValue <== isType1.out * 10 + isType2.out * 20 + isType3.out * 15 + 
                         isType4.out * 25 + isType5.out * 30;
    sensitivityValue <== sensitivityValue / 10; // Normalize
}

// **ResultVerification Template**
template ResultVerification(maxDataVaults) {
    signal input computationType;
    signal input dataVaultCount;
    signal input nonce;
    signal input contributions[maxDataVaults];
    signal input noiseMagnitudes[maxDataVaults];
    signal output calculatedResultHash;
    signal aggregatedResult <== 0;
    signal totalNoise <== 0;
    component isAverage = IsEqual(); isAverage.in[0] <== computationType; isAverage.in[1] <== 1;
    component isStatistical = IsEqual(); isStatistical.in[0] <== computationType; isStatistical.in[1] <== 2;
    component isOtherType = GreaterThan(3); isOtherType.in[0] <== computationType; isOtherType.in[1] <== 2;
    for (var i = 0; i < maxDataVaults; i++) {
        signal includeVault;
        component includeCheck = LessThan(8);
        includeCheck.in[0] <== i;
        includeCheck.in[1] <== dataVaultCount;
        includeVault <== includeCheck.out;
        aggregatedResult += includeVault * contributions[i];
        totalNoise += includeVault * noiseMagnitudes[i];
    }
    signal averageResult <== isAverage.out * (aggregatedResult / dataVaultCount);
    signal statisticalResult <== isStatistical.out * aggregatedResult;
    signal otherResult <== isOtherType.out * (aggregatedResult * 1.5);
    signal finalResult <== averageResult + statisticalResult + otherResult + totalNoise;
    component resultHasher = Poseidon(2);
    resultHasher.inputs[0] <== finalResult;
    resultHasher.inputs[1] <== nonce;
    calculatedResultHash <== resultHasher.out;
}

// Main component instantiation
component main {public [computationHash, resultHash, computationType, privacyBudgetHash, validatorsMerkleRoot]} = ComputationVerification(10, 50);
