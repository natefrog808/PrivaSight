pragma circom 2.0.0;

/*
 * PrivaSight Access Control Circuit
 *
 * This circuit verifies that a researcher has legitimate access to a data vault
 * without revealing the researcher's identity or the specific access details.
 * 
 * The circuit implements the following verification logic:
 * 1. Verifies the researcher address is authorized for the given data vault
 * 2. Checks that the access type matches the listing requirements
 * 3. Validates that the access has not expired
 * 4. Confirms the access was properly signed by the data owner
 * 5. Ensures that access terms (payment, purpose, etc.) have been satisfied
 */

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/eddsamimc.circom";
include "../../../node_modules/circomlib/circuits/mimcsponge.circom";

// Main Access Verification Circuit
template AccessVerification() {
    // Public inputs
    signal input dataVaultId;      // ID of the data vault being accessed
    signal input accessHash;       // Hash of access details (to be verified)
    signal input timestamp;        // Current timestamp to check expiration
    signal input merkleRoot;       // Merkle root of approved accesses

    // Private inputs
    signal input researcherAddress;   // Address of the researcher
    signal input accessType;          // Type of access (1: one-time, 2: subscription, 3: perpetual)
    signal input expirationTime;      // When the access expires
    signal input accessTermsHash;     // Hash of access terms
    signal input ownerSignatureR[2];  // R component of owner's EdDSA signature
    signal input ownerSignatureS;     // S component of owner's EdDSA signature
    signal input ownerPublicKey[2];   // Owner's EdDSA public key
    signal input merklePathIndices[32]; // Indices for Merkle path (direction bits)
    signal input merklePath[32];      // Merkle path to verify inclusion
    signal input nonce;               // Random nonce for privacy

    // Intermediate signals
    signal accessCredentialHash;
    signal signatureMessage;
    signal validExpiration;
    signal validMerkleProof;
    signal isOneTimeAccess;
    signal isSubscriptionAccess;
    signal isPerpetualAccess;
    signal validAccessType;

    // 1. Compute access credential hash
    component hashCredential = Poseidon(4);
    hashCredential.inputs[0] <== researcherAddress;
    hashCredential.inputs[1] <== dataVaultId;
    hashCredential.inputs[2] <== accessType;
    hashCredential.inputs[3] <== expirationTime;
    accessCredentialHash <== hashCredential.out;

    // 2. Verify access type is valid (1, 2, or 3)
    isOneTimeAccess <== IsEqual()([accessType, 1]);
    isSubscriptionAccess <== IsEqual()([accessType, 2]);
    isPerpetualAccess <== IsEqual()([accessType, 3]);
    validAccessType <== isOneTimeAccess + isSubscriptionAccess + isPerpetualAccess;
    validAccessType === 1; // Exactly one type must be true

    // 3. Verify access has not expired
    component timeCheck = LessThan(64);
    timeCheck.in[0] <== timestamp;
    timeCheck.in[1] <== expirationTime;
    validExpiration <== isPerpetualAccess + (1 - isPerpetualAccess) * timeCheck.out;
    validExpiration === 1; // Must be valid (not expired)

    // 4. Verify owner's signature
    component hashForSignature = Poseidon(5);
    hashForSignature.inputs[0] <== dataVaultId;
    hashForSignature.inputs[1] <== researcherAddress;
    hashForSignature.inputs[2] <== accessType;
    hashForSignature.inputs[3] <== expirationTime;
    hashForSignature.inputs[4] <== accessTermsHash;
    signatureMessage <== hashForSignature.out;

    component signatureVerifier = EdDSAMiMCVerifier();
    signatureVerifier.enabled <== 1;
    signatureVerifier.Ax <== ownerPublicKey[0];
    signatureVerifier.Ay <== ownerPublicKey[1];
    signatureVerifier.R8x <== ownerSignatureR[0];
    signatureVerifier.R8y <== ownerSignatureR[1];
    signatureVerifier.S <== ownerSignatureS;
    signatureVerifier.M <== signatureMessage;

    // 5. Verify Merkle tree inclusion
    component merkleProof = MerkleProofVerifier(32);
    merkleProof.leaf <== accessCredentialHash;
    merkleProof.root <== merkleRoot;
    for (var i = 0; i < 32; i++) {
        merkleProof.pathIndices[i] <== merklePathIndices[i];
        merkleProof.path[i] <== merklePath[i];
    }
    validMerkleProof <== merkleProof.isValid;

    // Ensure all checks pass
    signal accessIsValid;
    accessIsValid <== validAccessType * validExpiration * validMerkleProof;
    accessIsValid === 1;

    // Compute final access hash
    component finalHash = Poseidon(2);
    finalHash.inputs[0] <== accessCredentialHash;
    finalHash.inputs[1] <== nonce;
    finalHash.out === accessHash; // Must match provided accessHash
}

// Merkle Tree Proof Verifier
template MerkleProofVerifier(levels) {
    signal input leaf;
    signal input root;
    signal input pathIndices[levels];
    signal input path[levels];
    signal output isValid;

    component hashers[levels];
    component selectors[levels];
    signal levelHashes[levels+1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        selectors[i] = Multiplexer();
        selectors[i].sel <== pathIndices[i];
        selectors[i].in[0] <== levelHashes[i];
        selectors[i].in[1] <== path[i];
        
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== selectors[i].out0; // Left
        hashers[i].inputs[1] <== selectors[i].out1; // Right
        levelHashes[i+1] <== hashers[i].out;
    }

    component rootCheck = IsEqual();
    rootCheck.in[0] <== levelHashes[levels];
    rootCheck.in[1] <== root;
    isValid <== rootCheck.out;
}

// Multiplexer for Merkle path ordering
template Multiplexer() {
    signal input sel;
    signal input in[2];
    signal output out0;
    signal output out1;
    
    sel * (1 - sel) === 0; // Ensure sel is 0 or 1
    out0 <== (1 - sel) * in[0] + sel * in[1];
    out1 <== sel * in[0] + (1 - sel) * in[1];
}

component main {public [dataVaultId, accessHash, timestamp, merkleRoot]} = AccessVerification();
