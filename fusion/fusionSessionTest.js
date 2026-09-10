"use strict";

/*
 * Guardian X — Multi-Sensor Fusion Session Tests
 *
 * These tests verify:
 *   - Multiple independently-authorized sensors can fuse together.
 *   - RGB, thermal, and night-vision observations remain tied
 *     to their own authorization.
 *   - Geographic boundaries are enforced.
 *   - Unknown/unauthorized observations are rejected.
 *   - Expired authorizations are rejected.
 *   - Sensor/authorization mismatches are rejected.
 *   - Closed fusion sessions cannot continue operating.
 *   - Privacy protections remain enabled.
 *
 * This test does NOT activate real hardware.
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
} = require("./fusionEngine");

const {
  SESSION_STATUS,
  createFusionSession,
  fuseSessionObservations,
  closeFusionSession,
  getFusionSessionStatus,
} = require("./fusionSession");

const {
  APPROVER_ROLES,
  APPROVER_STATUS,
  createVerifiedApproval,
} = require("./approverPolicy");

/* =========================================================
   TEST HELPERS
   ========================================================= */

function isoOffset(baseDate, minutes) {
  return new Date(
    baseDate.getTime() + minutes * 60 * 1000
  ).toISOString();
}

function createAuthorization({
  incident,
  sensorType,
  allowedOutputs,
  now,
}) {
  const approver = {
    approverId: `guardian-test-approver-${sensorType}`,
    role: APPROVER_ROLES.INCIDENT_SUPERVISOR,
    status: APPROVER_STATUS.ACTIVE,
  };

  const approvalResult = createVerifiedApproval({
    incident,
    approver,
    sensorType,
    requestedBy: "guardian-test-user",
  });

  assert.strictEqual(
    approvalResult.success,
    true,
    `Verified approval creation failed for ${sensorType}: ${
      approvalResult.errors
        ? approvalResult.errors.join(", ")
        : "unknown error"
    }`
  );

  const result = createSensorAuthorization(
    {
      incidentId: incident.incidentId,

      sensorType,

      purpose:
        PURPOSES.SEARCH_AND_RESCUE,

      geographicBoundary: {
        latitude: 19.4326,
        longitude: -99.1332,
        radiusMeters: 1000,
      },

      requestedBy:
        "guardian-test-user",

      approval:
        approvalResult.approval,

      /*
       * Authorization begins one minute before
       * the test and remains active for ten more.
       */
      startsAt:
        isoOffset(now, -1),

      expiresAt:
        isoOffset(now, 10),

      dataRetentionUntil:
        isoOffset(now, 60),

      allowedOutputs,
    },
    incident
  );

  assert.strictEqual(
    result.authorized,
    true,
    `Authorization creation failed for ${sensorType}: ${
      result.errors
        ? result.errors.join(", ")
        : "unknown error"
    }`
  );

  return result.authorization;
      }

function buildObservation({
  authorization,
  observationType,
  confidence,
  latitude,
  longitude,
  summary,
  now,
}) {
  return {
    authorizationId:
      authorization.authorizationId,

    sensorType:
      authorization.sensorType,

    observationType,

    confidence,

    location: {
      latitude,
      longitude,
    },

    timestamp:
      new Date(now).toISOString(),

    summary,

    metadata: {
      altitude: 80,
      sensorHealth: "OK",
      platformId:
        "GX-TEST-DRONE-001",

      /*
       * This field is intentionally not on
       * the metadata allowlist and should
       * therefore never be preserved.
       */
      unsafeExtraField:
        "SHOULD_NOT_SURVIVE",
    },
  };
}

/* =========================================================
   MAIN TEST
   ========================================================= */

async function runTests() {
  console.log(
    "Starting Guardian X multi-sensor fusion tests..."
  );

  const now = new Date();

  const incident = {
    incidentId:
      "GX-MULTI-TEST-001",

    status:
      "ACTIVE",
  };

  /* =======================================================
     CREATE THREE INDEPENDENT SENSOR AUTHORIZATIONS
     ======================================================= */

  const rgbAuthorization =
    createAuthorization({
      incident,

      sensorType:
        SENSOR_TYPES.DRONE_RGB,

      allowedOutputs: [
        ALLOWED_OUTPUTS
          .DETECTION_SUMMARY,

        ALLOWED_OUTPUTS
          .EMERGENCY_MAP,
      ],

      now,
    });

  const thermalAuthorization =
    createAuthorization({
      incident,

      sensorType:
        SENSOR_TYPES.DRONE_THERMAL,

      allowedOutputs: [
        ALLOWED_OUTPUTS
          .THERMAL_ALERT,

        ALLOWED_OUTPUTS
          .EMERGENCY_MAP,
      ],

      now,
    });

  const nightVisionAuthorization =
    createAuthorization({
      incident,

      sensorType:
        SENSOR_TYPES
          .DRONE_NIGHT_VISION,

      allowedOutputs: [
        ALLOWED_OUTPUTS
          .DETECTION_SUMMARY,

        ALLOWED_OUTPUTS
          .EMERGENCY_MAP,
      ],

      now,
    });

  const authorizations = [
    rgbAuthorization,
    thermalAuthorization,
    nightVisionAuthorization,
  ];

  assert.notStrictEqual(
    rgbAuthorization.authorizationId,
    thermalAuthorization.authorizationId
  );

  assert.notStrictEqual(
    thermalAuthorization.authorizationId,
    nightVisionAuthorization.authorizationId
  );

  console.log(
    "✓ Independent sensor authorizations created"
  );

  /* =======================================================
     CREATE MULTI-SENSOR SESSION
     ======================================================= */

  const sessionCreation =
    createFusionSession({
      incident,

      authorizations,

      createdBy:
        "guardian-test-operator",

      now,
    });

  assert.strictEqual(
    sessionCreation.success,
    true,
    sessionCreation.error
  );

  const session =
    sessionCreation.session;

  assert.ok(
    session.sessionId
  );

  assert.strictEqual(
    session.status,
    SESSION_STATUS.ACTIVE
  );

  assert.strictEqual(
    session.authorizationIds.length,
    3
  );

  assert.strictEqual(
    session.sensorTypes.length,
    3
  );

  assert.strictEqual(
    session.privacyControls
      .emergencyScoped,
    true
  );

  assert.strictEqual(
    session.privacyControls
      .independentSensorAuthorizationRequired,
    true
  );

  assert.strictEqual(
    session.privacyControls
      .geographicBoundaryEnforced,
    true
  );

  assert.strictEqual(
    session.privacyControls
      .faceRecognitionEnabled,
    false
  );

  assert.strictEqual(
    session.privacyControls
      .persistentIdentityTrackingEnabled,
    false
  );

  assert.strictEqual(
    session.privacyControls
      .unrestrictedBackgroundSurveillanceEnabled,
    false
  );

  console.log(
    "✓ Multi-sensor fusion session created"
  );

  /* =======================================================
     CREATE VALID OBSERVATIONS
     ======================================================= */

  const rgbObservation =
    buildObservation({
      authorization:
        rgbAuthorization,

      observationType:
        OBSERVATION_TYPES
          .VISUAL_DETECTION,

      confidence: 0.9,

      latitude: 19.4327,
      longitude: -99.1331,

      summary:
        "Authorized RGB emergency observation.",

      now,
    });

  const thermalObservation =
    buildObservation({
      authorization:
        thermalAuthorization,

      observationType:
        OBSERVATION_TYPES
          .THERMAL_DETECTION,

      confidence: 0.96,

      latitude: 19.4328,
      longitude: -99.133,

      summary:
        "Authorized thermal emergency observation.",

      now,
    });

  const nightVisionObservation =
    buildObservation({
      authorization:
        nightVisionAuthorization,

      observationType:
        OBSERVATION_TYPES
          .NIGHT_VISION_DETECTION,

      confidence: 0.84,

      latitude: 19.4325,
      longitude: -99.1333,

      summary:
        "Authorized night-vision emergency observation.",

      now,
    });

  /* =======================================================
     TRUE MULTI-SENSOR FUSION
     ======================================================= */

  const fusion =
    fuseSessionObservations({
      session,

      incident,

      authorizations,

      observations: [
        rgbObservation,
        thermalObservation,
        nightVisionObservation,
      ],

      now,
    });

  assert.strictEqual(
    fusion.success,
    true,
    fusion.error
  );

  const fusionResult =
    fusion.fusionResult;

  assert.ok(
    fusionResult.fusionId
  );

  assert.strictEqual(
    fusionResult.sessionId,
    session.sessionId
  );

  assert.strictEqual(
    fusionResult.incidentId,
    incident.incidentId
  );

  assert.strictEqual(
    fusionResult.observations.length,
    3
  );

  assert.strictEqual(
    fusionResult.summary
      .totalObservations,
    3
  );

  assert.strictEqual(
    fusionResult.summary.sensorCount,
    3
  );

  /*
   * Average:
   * 0.90 + 0.96 + 0.84 = 2.70
   * 2.70 / 3 = 0.90
   */
  assert.strictEqual(
    fusionResult.confidence,
    0.9
  );

  assert.ok(
    fusionResult.outputs.includes(
      ALLOWED_OUTPUTS
        .EMERGENCY_MAP
    )
  );

  assert.ok(
    fusionResult.outputs.includes(
      ALLOWED_OUTPUTS
        .THERMAL_ALERT
    )
  );

  assert.ok(
    fusionResult.outputs.includes(
      ALLOWED_OUTPUTS
        .DETECTION_SUMMARY
    )
  );

  assert.strictEqual(
    fusionResult.privacyControls
      .faceRecognitionEnabled,
    false
  );

  assert.strictEqual(
    fusionResult.privacyControls
      .persistentIdentityTrackingEnabled,
    false
  );

  assert.strictEqual(
    fusionResult.privacyControls
      .unrestrictedBackgroundSurveillanceEnabled,
    false
  );

  console.log(
    "✓ RGB + thermal + night vision fused successfully"
  );

  /* =======================================================
     METADATA ALLOWLIST TEST
     ======================================================= */

  for (
    const observation
    of fusionResult.observations
  ) {
    assert.strictEqual(
      Object.prototype.hasOwnProperty.call(
        observation.metadata,
        "unsafeExtraField"
      ),
      false
    );
  }

  console.log(
    "✓ Unapproved metadata was removed"
  );

  /* =======================================================
     UNKNOWN AUTHORIZATION MUST FAIL
     ======================================================= */

  const unauthorizedObservation = {
    ...rgbObservation,

    authorizationId:
      "sensor_NOT_AUTHORIZED",
  };

  const unauthorizedFusion =
    fuseSessionObservations({
      session,

      incident,

      authorizations,

      observations: [
        unauthorizedObservation,
      ],

      now,
    });

  assert.strictEqual(
    unauthorizedFusion.success,
    false
  );

  console.log(
    "✓ Unknown authorization rejected"
  );

  /* =======================================================
     OUT-OF-BOUNDARY OBSERVATION MUST FAIL
     ======================================================= */

  const outsideBoundaryObservation = {
    ...thermalObservation,

    location: {
      latitude: 20.0,
      longitude: -100.0,
    },
  };

  const outsideBoundaryFusion =
    fuseSessionObservations({
      session,

      incident,

      authorizations,

      observations: [
        outsideBoundaryObservation,
      ],

      now,
    });

  assert.strictEqual(
    outsideBoundaryFusion.success,
    false
  );

  console.log(
    "✓ Out-of-boundary observation rejected"
  );

  /* =======================================================
     SENSOR / AUTHORIZATION MISMATCH MUST FAIL
     ======================================================= */

  const mismatchedObservation = {
    ...rgbObservation,

    sensorType:
      SENSOR_TYPES.DRONE_THERMAL,
  };

  const mismatchFusion =
    fuseSessionObservations({
      session,

      incident,

      authorizations,

      observations: [
        mismatchedObservation,
      ],

      now,
    });

  assert.strictEqual(
    mismatchFusion.success,
    false
  );

  console.log(
    "✓ Sensor/authorization mismatch rejected"
  );

  /* =======================================================
     EXPIRED AUTHORIZATION MUST FAIL
     ======================================================= */

  const expiredAuthorization = {
    ...thermalAuthorization,

    authorizationId:
      "sensor_EXPIRED_TEST",

    startsAt:
      isoOffset(now, -20),

    expiresAt:
      isoOffset(now, -10),

    status:
      "AUTHORIZED",
  };

  const expiredSessionAttempt =
    createFusionSession({
      incident,

      authorizations: [
        rgbAuthorization,
        expiredAuthorization,
      ],

      createdBy:
        "guardian-test-operator",

      now,
    });

  assert.strictEqual(
    expiredSessionAttempt.success,
    false
  );

  console.log(
    "✓ Expired sensor authorization rejected"
  );

  /* =======================================================
     CLOSED SESSION MUST STOP FUSION
     ======================================================= */

  const closeResult =
    closeFusionSession({
      session,

      closedBy:
        "guardian-test-operator",

      authorization:
        rgbAuthorization,

      now,
    });

  assert.strictEqual(
    closeResult.success,
    true,
    closeResult.error
  );

  assert.strictEqual(
    closeResult.session.status,
    SESSION_STATUS.CLOSED
  );

  const closedSessionFusion =
    fuseSessionObservations({
      session:
        closeResult.session,

      incident,

      authorizations,

      observations: [
        rgbObservation,
      ],

      now,
    });

  assert.strictEqual(
    closedSessionFusion.success,
    false
  );

  console.log(
    "✓ Closed session rejects further fusion"
  );

  /* =======================================================
     ENGINE SAFETY STATUS
     ======================================================= */

  const status =
    getFusionSessionStatus();

  assert.strictEqual(
    status.multiSensorFusion,
    true
  );

  assert.strictEqual(
    status.independentSensorAuthorizationRequired,
    true
  );

  assert.strictEqual(
    status.geographicBoundaryEnforced,
    true
  );

  assert.strictEqual(
    status.outputPermissionEnforced,
    true
  );

  assert.strictEqual(
    status.hardwareActivation,
    false
  );

  assert.strictEqual(
    status.faceRecognitionEnabled,
    false
  );

  assert.strictEqual(
    status.persistentIdentityTrackingEnabled,
    false
  );

  assert.strictEqual(
    status.unrestrictedBackgroundSurveillanceEnabled,
    false
  );

  console.log(
    "✓ Fusion session privacy safeguards verified"
  );

  console.log("");
  console.log(
    "ALL GUARDIAN X MULTI-SENSOR FUSION TESTS PASSED"
  );
}

/* =========================================================
   RUN
   ========================================================= */

runTests().catch((error) => {
  console.error("");
  console.error(
    "GUARDIAN X MULTI-SENSOR FUSION TEST FAILED"
  );

  console.error(error);

  process.exitCode = 1;
});
