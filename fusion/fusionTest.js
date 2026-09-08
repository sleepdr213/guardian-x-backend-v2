"use strict";

/*
 * Guardian X — Fusion Engine Test
 *
 * Tests:
 *  1. Valid sensor authorization
 *  2. Valid fusion observation
 *  3. Out-of-boundary observation rejection
 *  4. Expired authorization rejection
 *
 * This test does NOT activate hardware or contact real sensors.
 */

const assert = require("assert");

const {
  SENSOR_TYPES,
  PURPOSES,
  ALLOWED_OUTPUTS,
  createSensorAuthorization,
} = require("./sensorPolicy");

const {
  OBSERVATION_TYPES,
  fuseObservations,
  getFusionEngineStatus,
} = require("./fusionEngine");

/* =========================================================
   TEST HELPERS
   ========================================================= */

function minutesFromNow(minutes) {
  return new Date(Date.now() + minutes * 60 * 1000);
}

function logSuccess(message) {
  console.log(`PASS: ${message}`);
}

function runTests() {
  console.log("\nGuardian X Fusion Engine Tests\n");

  /* =======================================================
     TEST INCIDENT
     ======================================================= */

  const incident = {
    incidentId: "GX-TEST-001",
    status: "ACTIVE",
  };

  /* =======================================================
     TEST 1 — CREATE VALID AUTHORIZATION
     ======================================================= */

  const request = {
    incidentId: incident.incidentId,

    sensorType: SENSOR_TYPES.DRONE_THERMAL,

    purpose: PURPOSES.SEARCH_AND_RESCUE,

    geographicBoundary: {
      latitude: 19.4326,
      longitude: -99.1332,
      radiusMeters: 1000,
    },

    requestedBy: "test-user",

    approvedBy: "test-authorized-operator",

    startsAt: minutesFromNow(-1),

    expiresAt: minutesFromNow(10),

    dataRetentionUntil: minutesFromNow(60),

    allowedOutputs: [
      ALLOWED_OUTPUTS.THERMAL_ALERT,
      ALLOWED_OUTPUTS.EMERGENCY_MAP,
    ],
  };

  const authorizationResult =
    createSensorAuthorization(request, incident);

  assert.strictEqual(
    authorizationResult.authorized,
    true,
    `Authorization failed: ${
      authorizationResult.errors?.join(", ") || "unknown error"
    }`
  );

  const authorization =
    authorizationResult.authorization;

  logSuccess("Valid emergency sensor authorization created");

  /* =======================================================
     TEST 2 — VALID THERMAL OBSERVATION
     ======================================================= */

  const validObservation = {
    sensorType: SENSOR_TYPES.DRONE_THERMAL,

    observationType:
      OBSERVATION_TYPES.THERMAL_DETECTION,

    confidence: 0.92,

    location: {
      latitude: 19.4327,
      longitude: -99.1331,
    },

    timestamp: new Date(),

    summary:
      "Thermal observation detected inside authorized search area.",

    metadata: {
      altitude: 80,
      sensorHealth: "OK",
      platformId: "GUARDIAN-TEST-DRONE",
    },
  };

  const fusionResult = fuseObservations({
    authorization,
    incident,
    observations: [validObservation],
  });

  assert.strictEqual(
    fusionResult.success,
    true,
    `Fusion failed: ${
      fusionResult.errors?.join(", ") || "unknown error"
    }`
  );

  assert.strictEqual(
    fusionResult.fusionResult.incidentId,
    incident.incidentId
  );

  assert.strictEqual(
    fusionResult.fusionResult.confidence,
    0.92
  );

  assert.strictEqual(
    fusionResult.fusionResult.privacyControls
      .faceRecognitionEnabled,
    false
  );

  assert.strictEqual(
    fusionResult.fusionResult.privacyControls
      .persistentIdentityTrackingEnabled,
    false
  );

  logSuccess("Authorized thermal observation fused correctly");

  /* =======================================================
     TEST 3 — OUTSIDE AUTHORIZED AREA MUST FAIL
     ======================================================= */

  const outsideObservation = {
    ...validObservation,

    location: {
      latitude: 20.0,
      longitude: -100.0,
    },

    timestamp: new Date(),
  };

  const outsideResult = fuseObservations({
    authorization,
    incident,
    observations: [outsideObservation],
  });

  assert.strictEqual(
    outsideResult.success,
    false,
    "Out-of-boundary observation should have been rejected"
  );

  logSuccess("Out-of-boundary observation rejected");

  /* =======================================================
     TEST 4 — EXPIRED AUTHORIZATION MUST FAIL
     ======================================================= */

  const expiredAuthorization = {
    ...authorization,

    startsAt: minutesFromNow(-20).toISOString(),
    expiresAt: minutesFromNow(-10).toISOString(),
  };

  const expiredResult = fuseObservations({
    authorization: expiredAuthorization,
    incident,
    observations: [validObservation],
  });

  assert.strictEqual(
    expiredResult.success,
    false,
    "Expired authorization should have been rejected"
  );

  logSuccess("Expired authorization rejected");

  /* =======================================================
     ENGINE STATUS
     ======================================================= */

  const status = getFusionEngineStatus();

  assert.strictEqual(
    status.authorizationRequired,
    true
  );

  assert.strictEqual(
    status.geographicBoundaryEnforced,
    true
  );

  assert.strictEqual(
    status.faceRecognitionEnabled,
    false
  );

  logSuccess("Fusion Engine security controls verified");

  console.log("\nALL GUARDIAN X FUSION TESTS PASSED\n");
}

/* =========================================================
   RUN
   ========================================================= */

try {
  runTests();
} catch (error) {
  console.error("\nGUARDIAN X FUSION TEST FAILED");
  console.error(error.message);
  process.exitCode = 1;
    }
