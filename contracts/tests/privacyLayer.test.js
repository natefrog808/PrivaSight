/**
 * PrivaSight Privacy Layer Test Cases
 *
 * This file contains comprehensive test scenarios to validate the privacy,
 * security, and functionality of the PrivaSight Privacy Layer. These tests
 * cover access control via Zero-Knowledge Proofs (ZKPs), secure computation
 * via Secure Multi-Party Computation (SMPC), and the integration of both components.
 */

const { ZKPAccessVerifier, SMPCOrchestrator, PrivaSightPrivacyLayer } = require('./privacy-layer-prototype');

// Test utilities
const assert = require('assert').strict;
const crypto = require('crypto');

/**
 * Generate a deterministic hash for testing
 * @param {any} data - Data to hash
 * @returns {string} - Hash string
 */
function hashForTest(data) {
  return crypto.createHash('sha256')
    .update(typeof data === 'string' ? data : JSON.stringify(data))
    .digest('hex');
}

// --------------------------------------------------
// TEST CASE 1: VALID ACCESS AND COMPUTATION
// --------------------------------------------------
/**
 * Test Case: Valid Access and Computation
 *
 * Description:
 * A researcher with proper credentials from "University Medical Center" researching
 * "diabetes-research" requests access to three DataVaults with matching access rules.
 * The system should grant access, perform the computation, and return valid results.
 *
 * Expected Outcome:
 * - Access granted to all three DataVaults
 * - Computation completes successfully
 * - Results are aggregated and anonymized (e.g., average glucose levels by medication)
 * - No raw data (e.g., patient IDs) is exposed
 */
async function testValidAccessAndComputation() {
  console.log('=== TEST CASE 1: VALID ACCESS AND COMPUTATION ===');

  // Initialize the privacy layer
  const privacyLayer = await new PrivaSightPrivacyLayer().initialize();

  // 1. Setup test data
  const researcherCredentials = {
    id: 'researcher-123',
    name: 'Dr. Alice Johnson',
    organization: 'University Medical Center',
    purpose: 'diabetes-research',
    compensation: 50
  };

  const accessRules = new Map([
    ['vault-1', {
      category: 'medical',
      allowedPurposes: ['diabetes-research', 'heart-disease-research'],
      allowedOrganizations: ['University Medical Center', 'National Health Institute'],
      minCompensation: 30
    }],
    ['vault-2', {
      category: 'medical',
      allowedPurposes: ['diabetes-research', 'cancer-research'],
      allowedOrganizations: ['University Medical Center', 'Cancer Research Center'],
      minCompensation: 40
    }],
    ['vault-3', {
      category: 'medical',
      allowedPurposes: ['diabetes-research'],
      allowedOrganizations: ['University Medical Center'],
      minCompensation: 45
    }]
  ]);

  const encryptedData = new Map([
    ['vault-1', {
      patientId: 'ENC_patient-001',
      glucoseLevels: [
        { timestamp: 'ENC_2023-01-01', value: 'ENC_120' },
        { timestamp: 'ENC_2023-01-02', value: 'ENC_135' },
        { timestamp: 'ENC_2023-01-03', value: 'ENC_128' }
      ],
      medication: 'ENC_metformin',
      age: 'ENC_42',
      gender: 'ENC_female'
    }],
    ['vault-2', {
      patientId: 'ENC_patient-002',
      glucoseLevels: [
        { timestamp: 'ENC_2023-01-01', value: 'ENC_145' },
        { timestamp: 'ENC_2023-01-02', value: 'ENC_138' },
        { timestamp: 'ENC_2023-01-03', value: 'ENC_142' }
      ],
      medication: 'ENC_insulin',
      age: 'ENC_57',
      gender: 'ENC_male'
    }],
    ['vault-3', {
      patientId: 'ENC_patient-003',
      glucoseLevels: [
        { timestamp: 'ENC_2023-01-01', value: 'ENC_155' },
        { timestamp: 'ENC_2023-01-02', value: 'ENC_148' },
        { timestamp: 'ENC_2023-01-03', value: 'ENC_151' }
      ],
      medication: 'ENC_metformin',
      age: 'ENC_63',
      gender: 'ENC_female'
    }]
  ]);

  const computationRequest = {
    requestId: 'req-test-001',
    researcherId: researcherCredentials.id,
    purpose: 'diabetes-research',
    algorithm: 'average-glucose-by-medication',
    dataVaultIds: ['vault-1', 'vault-2', 'vault-3'],
    parameters: {
      organization: 'University Medical Center',
      timeRange: { start: '2023-01-01', end: '2023-01-03' },
      includeAgeAndGender: true
    },
    compensation: 50
  };

  // 2. Execute the test
  try {
    console.log('Executing computation request...');
    const result = await privacyLayer.processComputationRequest(
      computationRequest, accessRules, encryptedData
    );

    // 3. Validate the results
    console.log('Validating results...');

    // Basic structure checks
    assert(result, 'Result should exist');
    assert.strictEqual(result.requestId, computationRequest.requestId, 'Request ID should match');
    assert(result.aggregatedResults, 'Should have aggregated results');
    assert(result.resultHash, 'Should have a result hash');
    assert(result.zkProof, 'Should have a ZK proof');

    // Verify aggregated results specific to the algorithm
    const medications = Object.keys(result.aggregatedResults.results);
    assert(medications.includes('metformin'), 'Results should include metformin');
    assert(medications.includes('insulin'), 'Results should include insulin');
    assert(typeof result.aggregatedResults.results.metformin.glucoseAverage === 'number', 
           'Metformin glucose average should be a number');
    assert(typeof result.aggregatedResults.results.insulin.glucoseAverage === 'number', 
           'Insulin glucose average should be a number');

    // Ensure no raw data is exposed
    const resultStr = JSON.stringify(result);
    assert(!resultStr.includes('patient-001'), 'Should not expose patient ID from vault-1');
    assert(!resultStr.includes('patient-002'), 'Should not expose patient ID from vault-2');
    assert(!resultStr.includes('patient-003'), 'Should not expose patient ID from vault-3');
    assert(!resultStr.includes('ENC_'), 'Should not expose encrypted raw data');

    console.log('✅ TEST PASSED: Valid access and computation worked correctly');
    return true;
  } catch (error) {
    console.error('❌ TEST FAILED:', error.message);
    return false;
  }
}

// --------------------------------------------------
// TEST CASE 2: ACCESS DENIAL
// --------------------------------------------------
/**
 * Test Case: Access Denial
 *
 * Description:
 * A researcher with "cancer-research" purpose and limited compensation tries to access
 * DataVaults. The system should deny access where rules don't match but process allowed ones.
 *
 * Expected Outcome:
 * - Access denied to DataVaults with non-matching purpose or insufficient compensation
 * - Access granted to compatible DataVaults (vault-2 in this case)
 * - Computation proceeds with only authorized DataVaults
 */
async function testAccessDenial() {
  console.log('=== TEST CASE 2: ACCESS DENIAL ===');

  // Initialize the privacy layer
  const privacyLayer = await new PrivaSightPrivacyLayer().initialize();

  // 1. Setup test data
  const researcherCredentials = {
    id: 'researcher-456',
    name: 'Dr. Bob Smith',
    organization: 'University Medical Center',
    purpose: 'cancer-research',
    compensation: 50
  };

  const accessRules = new Map([
    ['vault-1', {
      category: 'medical',
      allowedPurposes: ['diabetes-research', 'heart-disease-research'],
      allowedOrganizations: ['University Medical Center', 'National Health Institute'],
      minCompensation: 30
    }],
    ['vault-2', {
      category: 'medical',
      allowedPurposes: ['diabetes-research', 'cancer-research'],
      allowedOrganizations: ['University Medical Center', 'Cancer Research Center'],
      minCompensation: 40
    }],
    ['vault-3', {
      category: 'medical',
      allowedPurposes: ['cancer-research'],
      allowedOrganizations: ['University Medical Center'],
      minCompensation: 60 // Requires more compensation than offered
    }]
  ]);

  const encryptedData = new Map([
    ['vault-1', { patientId: 'ENC_patient-001', diagnosisData: 'ENC_diabetes_type_2' }],
    ['vault-2', { patientId: 'ENC_patient-002', diagnosisData: 'ENC_breast_cancer_stage_1' }],
    ['vault-3', { patientId: 'ENC_patient-003', diagnosisData: 'ENC_lung_cancer_stage_2' }]
  ]);

  const computationRequest = {
    requestId: 'req-test-002',
    researcherId: researcherCredentials.id,
    purpose: 'cancer-research',
    algorithm: 'statistical-analysis',
    dataVaultIds: ['vault-1', 'vault-2', 'vault-3'],
    parameters: { organization: 'University Medical Center', analysisType: 'demographic-distribution' },
    compensation: 50
  };

  // 2. Execute the test
  try {
    console.log('Executing computation request...');
    const result = await privacyLayer.processComputationRequest(
      computationRequest, accessRules, encryptedData
    );

    // 3. Validate the results
    console.log('Validating results...');
    assert(result, 'Result should exist');
    assert.strictEqual(result.requestId, computationRequest.requestId, 'Request ID should match');

    // Only vault-2 should be processed (vault-1: wrong purpose, vault-3: insufficient compensation)
    const vaultsUsed = result.zkProof.dataVaultCount;
    assert.strictEqual(vaultsUsed, 1, 'Only one DataVault (vault-2) should have been processed');

    console.log('✅ TEST PASSED: Access denial worked correctly');
    return true;
  } catch (error) {
    if (error.message === 'Access denied to all requested DataVaults') {
      console.log('✅ TEST PASSED: Access denial worked correctly (all access denied)');
      return true;
    }
    console.error('❌ TEST FAILED:', error.message);
    return false;
  }
}

// --------------------------------------------------
// TEST CASE 3: SCALABILITY TEST
// --------------------------------------------------
/**
 * Test Case: Scalability Test
 *
 * Description:
 * Tests the system's ability to handle 50 DataVaults efficiently, measuring
 * execution time and memory usage.
 *
 * Expected Outcome:
 * - All DataVaults processed successfully
 * - Computation completes within 10 seconds
 * - Memory usage stays below 200 MB
 */
async function testScalability() {
  console.log('=== TEST CASE 3: SCALABILITY TEST ===');

  // Initialize the privacy layer
  const privacyLayer = await new PrivaSightPrivacyLayer().initialize();

  // 1. Setup test data
  const researcherCredentials = {
    id: 'researcher-789',
    name: 'Dr. Charlie Garcia',
    organization: 'National Health Institute',
    purpose: 'public-health-research',
    compensation: 25
  };

  const VAULT_COUNT = 50;
  const accessRules = new Map();
  const encryptedData = new Map();
  const vaultIds = [];

  console.log(`Generating ${VAULT_COUNT} test DataVaults...`);
  for (let i = 1; i <= VAULT_COUNT; i++) {
    const vaultId = `vault-${i}`;
    vaultIds.push(vaultId);
    accessRules.set(vaultId, {
      category: 'medical',
      allowedPurposes: ['public-health-research'],
      allowedOrganizations: ['National Health Institute'],
      minCompensation: 20
    });
    encryptedData.set(vaultId, {
      patientId: `ENC_patient-${1000 + i}`,
      age: `ENC_${20 + (i % 60)}`,
      gender: i % 2 === 0 ? 'ENC_female' : 'ENC_male'
    });
  }

  const computationRequest = {
    requestId: 'req-test-003',
    researcherId: researcherCredentials.id,
    purpose: 'public-health-research',
    algorithm: 'statistical-analysis',
    dataVaultIds: vaultIds,
    parameters: { organization: 'National Health Institute', analysisType: 'demographic-distribution' },
    compensation: 25
  };

  // 2. Execute the test with performance measurement
  console.log('Executing large-scale computation request...');
  const startTime = Date.now();
  const memoryBefore = process.memoryUsage().heapUsed;

  try {
    const result = await privacyLayer.processComputationRequest(
      computationRequest, accessRules, encryptedData
    );

    const endTime = Date.now();
    const memoryAfter = process.memoryUsage().heapUsed;
    const executionTime = endTime - startTime;
    const memoryUsage = (memoryAfter - memoryBefore) / 1024 / 1024; // MB

    // 3. Validate the results
    console.log('Validating results...');
    console.log(`Execution time: ${executionTime} ms`);
    console.log(`Memory usage: ${memoryUsage.toFixed(2)} MB`);

    assert(result, 'Result should exist');
    assert.strictEqual(result.requestId, computationRequest.requestId, 'Request ID should match');
    assert.strictEqual(result.zkProof.dataVaultCount, VAULT_COUNT, `All ${VAULT_COUNT} DataVaults should be processed`);

    // Performance thresholds (adjust based on real system requirements)
    assert(executionTime < 10000, 'Execution should complete in under 10 seconds');
    assert(memoryUsage < 200, 'Memory usage should be under 200 MB');

    console.log('✅ TEST PASSED: Scalability test completed successfully');
    return true;
  } catch (error) {
    console.error('❌ TEST FAILED:', error.message);
    return false;
  }
}

// --------------------------------------------------
// TEST CASE 4: PRIVACY GUARANTEE VERIFICATION
// --------------------------------------------------
/**
 * Test Case: Privacy Guarantee Verification
 *
 * Description:
 * Verifies that sensitive individual data remains private during computation by
 * checking logs and results for leaks.
 *
 * Expected Outcome:
 * - No sensitive data (e.g., patient IDs, HIV status) in logs or results
 * - Results contain only aggregated data
 */
async function testPrivacyGuarantees() {
  console.log('=== TEST CASE 4: PRIVACY GUARANTEE VERIFICATION ===');

  // Initialize the privacy layer
  const privacyLayer = await new PrivaSightPrivacyLayer().initialize();

  // 1. Setup test data
  const researcherCredentials = {
    id: 'researcher-101',
    name: 'Dr. Dana Lewis',
    organization: 'Public Health Department',
    purpose: 'covid-research',
    compensation: 60
  };

  const accessRules = new Map([
    ['vault-1', {
      category: 'medical',
      allowedPurposes: ['covid-research'],
      allowedOrganizations: ['Public Health Department'],
      minCompensation: 50
    }],
    ['vault-2', {
      category: 'medical',
      allowedPurposes: ['covid-research'],
      allowedOrganizations: ['Public Health Department'],
      minCompensation: 50
    }]
  ]);

  const SENSITIVE_VALUES = ['HIV_POSITIVE', '123-45-6789', 'SEVERE_DEPRESSION', 'BANKRUPTCY'];
  const encryptedData = new Map([
    ['vault-1', {
      patientId: 'ENC_patient-101',
      covidStatus: 'ENC_POSITIVE',
      preExistingCondition: `ENC_${SENSITIVE_VALUES[0]}`,
      socialSecurityNumber: `ENC_${SENSITIVE_VALUES[1]}`
    }],
    ['vault-2', {
      patientId: 'ENC_patient-102',
      covidStatus: 'ENC_NEGATIVE',
      mentalHealthDiagnosis: `ENC_${SENSITIVE_VALUES[2]}`,
      financialStatus: `ENC_${SENSITIVE_VALUES[3]}`
    }]
  ]);

  const computationRequest = {
    requestId: 'req-test-004',
    researcherId: researcherCredentials.id,
    purpose: 'covid-research',
    algorithm: 'statistical-analysis',
    dataVaultIds: ['vault-1', 'vault-2'],
    parameters: { organization: 'Public Health Department', analysisType: 'covid-status-by-age' },
    compensation: 60
  };

  // 2. Execute the test with log capture
  try {
    console.log('Executing computation with sensitive data...');
    const originalConsoleLog = console.log;
    const capturedLogs = [];
    console.log = (...args) => capturedLogs.push(args.join(' '));

    const result = await privacyLayer.processComputationRequest(
      computationRequest, accessRules, encryptedData
    );

    console.log = originalConsoleLog;

    // 3. Validate privacy guarantees
    console.log('Validating privacy guarantees...');
    const allOutput = [...capturedLogs, JSON.stringify(result)].join(' ');

    for (const sensitiveValue of SENSITIVE_VALUES) {
      assert(!allOutput.includes(sensitiveValue), `Sensitive data leaked: ${sensitiveValue}`);
    }
    assert(!allOutput.includes('patient-101'), 'Patient ID from vault-1 leaked');
    assert(!allOutput.includes('patient-102'), 'Patient ID from vault-2 leaked');
    assert(result.aggregatedResults, 'Result should contain aggregated data');
    assert(!JSON.stringify(result).includes('ENC_'), 'Results should not contain encrypted raw data');

    console.log('✅ TEST PASSED: Privacy guarantees verified');
    return true;
  } catch (error) {
    console.error('❌ TEST FAILED:', error.message);
    return false;
  }
}

// --------------------------------------------------
// TEST CASE 5: FAILURE HANDLING
// --------------------------------------------------
/**
 * Test Case: Failure Handling
 *
 * Description:
 * Tests system resilience under three failure scenarios: invalid ZKP proof,
 * SMPC node failure, and malformed data.
 *
 * Expected Outcome:
 * - Invalid ZKP proof denies access
 * - Node failure is detected and reported
 * - Malformed data is handled gracefully
 */
async function testFailureHandling() {
  console.log('=== TEST CASE 5: FAILURE HANDLING ===');

  const scenarios = ['invalid_zkp', 'node_failure', 'malformed_data'];
  let passCount = 0;

  for (const scenario of scenarios) {
    console.log(`\nTesting scenario: ${scenario}`);
    const privacyLayer = await new PrivaSightPrivacyLayer().initialize();

    const researcherCredentials = {
      id: 'researcher-202',
      name: 'Dr. Eve Wilson',
      organization: 'Research Institute',
      purpose: 'demographic-research',
      compensation: 40
    };

    const accessRules = new Map([
      ['vault-1', {
        category: 'demographic',
        allowedPurposes: ['demographic-research'],
        allowedOrganizations: ['Research Institute'],
        minCompensation: 30
      }]
    ]);

    const encryptedData = new Map([
      ['vault-1', {
        personId: 'ENC_person-202',
        age: 'ENC_28',
        income: 'ENC_75000',
        education: 'ENC_bachelors'
      }]
    ]);

    const computationRequest = {
      requestId: `req-test-005-${scenario}`,
      researcherId: researcherCredentials.id,
      purpose: 'demographic-research',
      algorithm: 'statistical-analysis',
      dataVaultIds: ['vault-1'],
      parameters: { organization: 'Research Institute', analysisType: 'income-by-education' },
      compensation: 40
    };

    try {
      switch (scenario) {
        case 'invalid_zkp':
          privacyLayer.zkpVerifier.verifyAccessProof = async () => false;
          break;
        case 'node_failure':
          privacyLayer.smpcOrchestrator.mpcNodes[0].compute = () => {
            throw new Error('Node failure during computation');
          };
          break;
        case 'malformed_data':
          encryptedData.set('vault-1', {
            personId: 'ENC_person-202',
            age: null,
            income: 'ENC_not_a_number',
            education: undefined
          });
          break;
      }

      console.log(`Executing computation with ${scenario} scenario...`);
      const result = await privacyLayer.processComputationRequest(
        computationRequest, accessRules, encryptedData
      );

      if (scenario === 'invalid_zkp') {
        assert(result.zkProof.dataVaultCount === 0, 'Invalid ZKP should deny access');
      } else if (scenario === 'node_failure') {
        assert(result.partialFailure || result.errorNodes, 'Node failure should be indicated');
      } else if (scenario === 'malformed_data') {
        assert(result.dataQualityIssues || result.warnings, 'Malformed data should be reported');
      }

      console.log(`✅ TEST PASSED: ${scenario} scenario handled correctly`);
      passCount++;
    } catch (error) {
      if (
        (scenario === 'invalid_zkp' && error.message.includes('Access denied')) ||
        (scenario === 'node_failure' && error.message.includes('node')) ||
        (scenario === 'malformed_data' && error.message.includes('data'))
      ) {
        console.log(`✅ TEST PASSED: ${scenario} scenario raised expected error: ${error.message}`);
        passCount++;
      } else {
        console.error(`❌ TEST FAILED for ${scenario}:`, error.message);
      }
    }
  }

  console.log(`\nFailure handling test complete: ${passCount}/${scenarios.length} scenarios passed`);
  return passCount === scenarios.length;
}

// --------------------------------------------------
// MAIN TEST RUNNER
// --------------------------------------------------
/**
 * Run all test cases and summarize results
 */
async function runAllTests() {
  console.log('============================================');
  console.log('PRIVASIGHT PRIVACY LAYER TEST SUITE');
  console.log('============================================\n');

  const testResults = {
    'Valid Access and Computation': await testValidAccessAndComputation(),
    'Access Denial': await testAccessDenial(),
    'Scalability': await testScalability(),
    'Privacy Guarantees': await testPrivacyGuarantees(),
    'Failure Handling': await testFailureHandling()
  };

  console.log('\n============================================');
  console.log('TEST RESULTS SUMMARY');
  console.log('============================================');

  let passCount = 0;
  for (const [testName, passed] of Object.entries(testResults)) {
    console.log(`${passed ? '✅ PASSED' : '❌ FAILED'}: ${testName}`);
    if (passed) passCount++;
  }

  const totalTests = Object.keys(testResults).length;
  console.log(`\n${passCount}/${totalTests} tests passed (${Math.round(passCount / totalTests * 100)}%)`);
  return passCount === totalTests;
}

// Uncomment to run tests automatically
// runAllTests().then(success => process.exit(success ? 0 : 1));

module.exports = {
  testValidAccessAndComputation,
  testAccessDenial,
  testScalability,
  testPrivacyGuarantees,
  testFailureHandling,
  runAllTests
};
