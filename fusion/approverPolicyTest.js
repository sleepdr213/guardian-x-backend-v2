"use strict";

/*
 * Guardian X — Approver Policy Tests
 *
 * Tests:
 *   1. Valid approver
 *   2. Valid approval creation
 *   3. Role-to-sensor restrictions
 *   4. Suspended approver rejection
 *   5. Revoked approver rejection
 *   6. Invalid role rejection
 *   7. Inactive incident rejection
 *   8. Approval/incident mismatch rejection
 *   9. Approval/sensor mismatch rejection
 *  10. Policy security controls
 *
 * These tests do NOT activate hardware or contact real sensors.
 */

const assert = require("assert");

const {
  APPROVER_ROLES,
  APPROVER_STATUS,
  SENSOR_TYPES,
  validateApprover,
  canRoleApproveSensor,
  createVerifiedApproval,
  verifyApprovalForSensor,
  getApproverPolicyStatus,
} = require("./approverPolicy");

/* ============================================================
   HELPERS
   ============================================================ */

function pass(message) {
  console.log(`PASS: ${message}`);
}

function expectFailure(result, message) {
  assert.strictEqual(
    result.success,
    false,
    message
  );
}

/* ============================================================
   TESTS
   ============================================================ */

function runTests() {
  console.log("\nGuardian X Approver Policy Tests\n");

  const activeIncident = {
    incidentId: "GX-APPROVER-TEST-001",
    status: "ACTIVE",
  };

  const activeSupervisor = {
    approverId: "test-supervisor-001",
    role: APPROVER_ROLES.INCIDENT_SUPERVISOR,
    status: APPROVER_STATUS.ACTIVE,
  };

  /* ==========================================================
     TEST 1 — VALID APPROVER
     ========================================================== */

  const approverValidation =
    validateApprover(activeSupervisor);

  assert.strictEqual(
    approverValidation.success,
    true,
    `Valid approver rejected: ${
      approverValidation.errors?.join(", ") ||
      "unknown error"
    }`
  );

  pass("Valid active approver accepted");

  /* ==========================================================
     TEST 2 — CREATE VALID APPROVAL
     ========================================================== */

  const approvalResult = createVerifiedApproval({
    incident: activeIncident,
    approver: activeSupervisor,
    sensorType: SENSOR_TYPES.DRONE_THERMAL,
    requestedBy: "test-user-001",
  });

  assert.strictEqual(
    approvalResult.success,
    true,
    `Valid approval rejected: ${
      approvalResult.errors?.join(", ") ||
      "unknown error"
    }`
  );

  assert.strictEqual(
    approvalResult.approval.incidentId,
    activeIncident.incidentId
  );

  assert.strictEqual(
    approvalResult.approval.sensorType,
    SENSOR_TYPES.DRONE_THERMAL
  );

  assert.strictEqual(
    approvalResult.approval.hardwareActivation,
    false
  );

  assert.strictEqual(
    approvalResult.approval.auditRequired,
    true
  );

  pass("Valid sensor approval created");

  /* ==========================================================
     TEST 3 — ROLE/SENSOR RESTRICTIONS
     ========================================================== */

  assert.strictEqual(
    canRoleApproveSensor(
      APPROVER_ROLES.DRONE_OPERATOR,
      SENSOR_TYPES.DRONE_THERMAL
    ),
    true
  );

  assert.strictEqual(
    canRoleApproveSensor(
      APPROVER_ROLES.DRONE_OPERATOR,
      SENSOR_TYPES.DRONE_WAMI
    ),
    false
  );

  assert.strictEqual(
    canRoleApproveSensor(
      APPROVER_ROLES.INCIDENT_SUPERVISOR,
      SENSOR_TYPES.DRONE_WAMI
    ),
    true
  );

  pass("Role-to-sensor approval boundaries enforced");

  /* ==========================================================
     TEST 4 — SUSPENDED APPROVER MUST FAIL
     ========================================================== */

  const suspendedApprover = {
    ...activeSupervisor,
    approverId: "test-suspended-001",
    status: APPROVER_STATUS.SUSPENDED,
  };

  const suspendedResult = createVerifiedApproval({
    incident: activeIncident,
    approver: suspendedApprover,
    sensorType: SENSOR_TYPES.DRONE_THERMAL,
    requestedBy: "test-user-001",
  });

  expectFailure(
    suspendedResult,
    "Suspended approver should have been rejected"
  );

  pass("Suspended approver rejected");

  /* ==========================================================
     TEST 5 — REVOKED APPROVER MUST FAIL
     ========================================================== */

  const revokedApprover = {
    ...activeSupervisor,
    approverId: "test-revoked-001",
    status: APPROVER_STATUS.REVOKED,
  };

  const revokedResult = createVerifiedApproval({
    incident: activeIncident,
    approver: revokedApprover,
    sensorType: SENSOR_TYPES.DRONE_THERMAL,
    requestedBy: "test-user-001",
  });

  expectFailure(
    revokedResult,
    "Revoked approver should have been rejected"
  );

  pass("Revoked approver rejected");

  /* ==========================================================
     TEST 6 — INVALID ROLE MUST FAIL
     ========================================================== */

  const invalidRoleApprover = {
    approverId: "test-invalid-role-001",
    role: "UNRESTRICTED_ADMIN",
    status: APPROVER_STATUS.ACTIVE,
  };

  const invalidRoleResult = createVerifiedApproval({
    incident: activeIncident,
    approver: invalidRoleApprover,
    sensorType: SENSOR_TYPES.DRONE_THERMAL,
    requestedBy: "test-user-001",
  });

  expectFailure(
    invalidRoleResult,
    "Unknown approver role should have been rejected"
  );

  pass("Unknown/unrestricted role rejected");

  /* ==========================================================
     TEST 7 — INACTIVE INCIDENT MUST FAIL
     ========================================================== */

  const closedIncident = {
    incidentId: "GX-APPROVER-TEST-CLOSED",
    status: "CLOSED",
  };

  const inactiveIncidentResult =
    createVerifiedApproval({
      incident: closedIncident,
      approver: activeSupervisor,
      sensorType: SENSOR_TYPES.DRONE_THERMAL,
      requestedBy: "test-user-001",
    });

  expectFailure(
    inactiveIncidentResult,
    "Inactive incident should have been rejected"
  );

  pass("Inactive incident rejected");

  /* ==========================================================
     TEST 8 — INCIDENT MISMATCH MUST FAIL
     ========================================================== */

  const differentIncident = {
    incidentId: "GX-APPROVER-TEST-OTHER",
    status: "ACTIVE",
  };

  const incidentMismatchResult =
    verifyApprovalForSensor({
      approval: approvalResult.approval,
      incident: differentIncident,
      sensorType: SENSOR_TYPES.DRONE_THERMAL,
    });

  expectFailure(
    incidentMismatchResult,
    "Approval should not work for another incident"
  );

  pass("Cross-incident approval reuse rejected");

  /* ==========================================================
     TEST 9 — SENSOR MISMATCH MUST FAIL
     ========================================================== */

  const sensorMismatchResult =
    verifyApprovalForSensor({
      approval: approvalResult.approval,
      incident: activeIncident,
      sensorType: SENSOR_TYPES.DRONE_RGB,
    });

  expectFailure(
    sensorMismatchResult,
    "Approval should not work for another sensor"
  );

  pass("Cross-sensor approval reuse rejected");

  /* ==========================================================
     TEST 10 — VALID APPROVAL VERIFICATION
     ========================================================== */

  const verificationResult =
    verifyApprovalForSensor({
      approval: approvalResult.approval,
      incident: activeIncident,
      sensorType: SENSOR_TYPES.DRONE_THERMAL,
    });

  assert.strictEqual(
    verificationResult.success,
    true,
    `Valid approval verification failed: ${
      verificationResult.errors?.join(", ") ||
      "unknown error"
    }`
  );

  pass("Valid approval verified");

  /* ==========================================================
     TEST 11 — POLICY SECURITY CONTROLS
     ========================================================== */

  const status = getApproverPolicyStatus();

  assert.strictEqual(
    status.failClosed,
    true
  );

  assert.strictEqual(
    status.approverIdentityRequired,
    true
  );

  assert.strictEqual(
    status.approverRoleRequired,
    true
  );

  assert.strictEqual(
    status.activeApproverRequired,
    true
  );

  assert.strictEqual(
    status.activeIncidentRequired,
    true
  );

  assert.strictEqual(
    status.roleSensorScopeEnforced,
    true
  );

  assert.strictEqual(
    status.auditRequired,
    true
  );

  assert.strictEqual(
    status.hardwareActivation,
    false
  );

  assert.strictEqual(
    status.unrestrictedApprovalAllowed,
    false
  );

  pass("Approver Policy security controls verified");

  console.log(
    "\nALL GUARDIAN X APPROVER POLICY TESTS PASSED\n"
  );
}

/* ============================================================
   RUN
   ============================================================ */

try {
  runTests();
} catch (error) {
  console.error(
    "\nGUARDIAN X APPROVER POLICY TEST FAILED"
  );

  console.error(error.message);

  process.exitCode = 1;
    }
