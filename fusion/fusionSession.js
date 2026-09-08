"use strict";

/*
 * Guardian X — Multi-Sensor Fusion Session
 *
 * Purpose:
 *   Allows observations from multiple independently-authorized sensors
 *   to contribute to one emergency-scoped fusion result.
 *
 * Security principles:
 *   - Every sensor requires its own active authorization.
 *   - Every observation must reference its authorization.
 *   - Geographic boundaries are enforced per sensor authorization.
 *   - Output permissions are enforced per authorization.
 *   - Active incident required.
 *   - Fail closed on invalid data.
 *   - No direct hardware activation.
 *   - No face recognition.
 *   - No persistent identity tracking.
 *   - No unrestricted/background surveillance.
 */

const crypto = require("crypto");

const {
  ALLOWED_OUTPUTS,
  isAuthorizationActive,
  isCoordinateWithinAuthorization,
  isOutputAllowed,
  buildAuditEvent,
} = require("./sensorPolicy");

const {
  OBSERVATION_TYPES,
  SENSOR_OBSERVATION_MAP,
} = require("./fusionEngine");

/* =========================================================
   SESSION CONFIGURATION
   ========================================================= */

const SESSION_CONFIG = Object.freeze({
  version: "1.0.1",

  maximumAuthorizations: 20,
  maximumObservations: 200,

  maximumObservationAgeSeconds: 120,
  maximumFutureObservationSeconds: 30,

  maximumSummaryLength: 500,
});

/* =========================================================
   SESSION STATUS
   ========================================================= */

const SESSION_STATUS = Object.freeze({
  ACTIVE: "ACTIVE",
  CLOSED: "CLOSED",
});

/* =========================================================
   BASIC HELPERS
   ========================================================= */

function createId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function isNonEmptyString(value) {
  return (
    typeof value === "string" &&
    value.trim().length > 0
  );
}

function isFiniteNumber(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value)
  );
}

function isValidCoordinate(latitude, longitude) {
  return (
    isFiniteNumber(latitude) &&
    isFiniteNumber(longitude) &&
    latitude >= -90 &&
    latitude <= 90 &&
    longitude >= -180 &&
    longitude <= 180
  );
}

function parseDate(value) {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date;
}

function safeText(value) {
  if (!isNonEmptyString(value)) {
    return null;
  }

  return value
    .trim()
    .slice(0, SESSION_CONFIG.maximumSummaryLength);
}

/* =========================================================
   SAFE METADATA
   ========================================================= */

function sanitizeMetadata(metadata) {
  if (
    !metadata ||
    typeof metadata !== "object" ||
    Array.isArray(metadata)
  ) {
    return {};
  }

  const allowedKeys = [
    "altitude",
    "speed",
    "heading",
    "temperature",
    "weatherCondition",
    "terrainType",
    "sensorHealth",
    "platformId",
  ];

  const safe = {};

  for (const key of allowedKeys) {
    if (
      Object.prototype.hasOwnProperty.call(
        metadata,
        key
      )
    ) {
      safe[key] = metadata[key];
    }
  }

  return safe;
}

/* =========================================================
   INCIDENT VALIDATION
   ========================================================= */

function validateIncident(incident) {
  if (
    !incident ||
    typeof incident !== "object"
  ) {
    return {
      valid: false,
      error: "Incident is required.",
    };
  }

  if (!isNonEmptyString(incident.incidentId)) {
    return {
      valid: false,
      error: "Incident ID is required.",
    };
  }

  if (incident.status !== "ACTIVE") {
    return {
      valid: false,
      error: "Incident must be ACTIVE.",
    };
  }

  return {
    valid: true,
  };
}

/* =========================================================
   AUTHORIZATION SET VALIDATION
   ========================================================= */

function validateAuthorizationSet({
  incident,
  authorizations,
  now = new Date(),
}) {
  const incidentValidation =
    validateIncident(incident);

  if (!incidentValidation.valid) {
    return incidentValidation;
  }

  if (
    !Array.isArray(authorizations) ||
    authorizations.length === 0
  ) {
    return {
      valid: false,
      error:
        "At least one sensor authorization is required.",
    };
  }

  if (
    authorizations.length >
    SESSION_CONFIG.maximumAuthorizations
  ) {
    return {
      valid: false,
      error:
        "Sensor authorization limit exceeded.",
    };
  }

  const authorizationIds = new Set();

  for (const authorization of authorizations) {
    if (
      !authorization ||
      typeof authorization !== "object"
    ) {
      return {
        valid: false,
        error: "Invalid sensor authorization.",
      };
    }

    if (
      !isNonEmptyString(
        authorization.authorizationId
      )
    ) {
      return {
        valid: false,
        error:
          "Authorization ID is required.",
      };
    }

    if (
      authorizationIds.has(
        authorization.authorizationId
      )
    ) {
      return {
        valid: false,
        error:
          "Duplicate authorization ID.",
      };
    }

    authorizationIds.add(
      authorization.authorizationId
    );

    if (
      authorization.incidentId !==
      incident.incidentId
    ) {
      return {
        valid: false,
        error:
          "Authorization does not belong to this incident.",
      };
    }

    if (
      !isAuthorizationActive(
        authorization,
        now
      )
    ) {
      return {
        valid: false,
        error:
          "Sensor authorization is not active.",
      };
    }

    if (
      !isNonEmptyString(
        authorization.sensorType
      )
    ) {
      return {
        valid: false,
        error:
          "Authorization sensor type is required.",
      };
    }

    if (
      !Array.isArray(
        SENSOR_OBSERVATION_MAP[
          authorization.sensorType
        ]
      )
    ) {
      return {
        valid: false,
        error:
          "Authorization sensor type is not supported.",
      };
    }
  }

  return {
    valid: true,
  };
}

/* =========================================================
   SESSION AUDIT HELPER
   ========================================================= */

function createSessionAuditEvent({
  action,
  authorization = null,
  success,
  reason = null,
  sessionId = null,
  fusionId = null,
}) {
  const event = buildAuditEvent(
    action,
    authorization,
    success,
    reason
  );

  return {
    ...event,

    sessionId:
      isNonEmptyString(sessionId)
        ? sessionId
        : null,

    fusionId:
      isNonEmptyString(fusionId)
        ? fusionId
        : null,
  };
}

/* =========================================================
   CREATE FUSION SESSION
   ========================================================= */

function createFusionSession({
  incident,
  authorizations,
  createdBy,
  now = new Date(),
}) {
  if (!isNonEmptyString(createdBy)) {
    return {
      success: false,
      error: "createdBy is required.",
    };
  }

  const validation =
    validateAuthorizationSet({
      incident,
      authorizations,
      now,
    });

  if (!validation.valid) {
    return {
      success: false,
      error: validation.error,
    };
  }

  const authorizationIds =
    authorizations.map(
      (authorization) =>
        authorization.authorizationId
    );

  const sensorTypes = [
    ...new Set(
      authorizations.map(
        (authorization) =>
          authorization.sensorType
      )
    ),
  ];

  const session = {
    sessionId: createId("GX_FUSION_SESSION"),

    fusionVersion:
      SESSION_CONFIG.version,

    incidentId:
      incident.incidentId,

    status:
      SESSION_STATUS.ACTIVE,

    createdBy:
      createdBy.trim(),

    createdAt:
      new Date(now).toISOString(),

    authorizationIds,

    sensorTypes,

    privacyControls: {
      emergencyScoped: true,

      independentSensorAuthorizationRequired:
        true,

      geographicBoundaryEnforced: true,

      outputPermissionEnforced: true,

      faceRecognitionEnabled: false,

      persistentIdentityTrackingEnabled:
        false,

      unrestrictedBackgroundSurveillanceEnabled:
        false,
    },
  };

  const primaryAuthorization =
    authorizations[0];

  const auditEvent =
    createSessionAuditEvent({
      action:
        "FUSION_SESSION_CREATED",

      authorization:
        primaryAuthorization,

      success: true,

      sessionId:
        session.sessionId,
    });

  return {
    success: true,
    session,
    auditEvent,
  };
}

/* =========================================================
   AUTHORIZATION LOOKUP
   ========================================================= */

function createAuthorizationMap(
  authorizations
) {
  return new Map(
    authorizations.map(
      (authorization) => [
        authorization.authorizationId,
        authorization,
      ]
    )
  );
}

function findAuthorizationForObservation(
  observation,
  authorizationMap
) {
  if (
    !observation ||
    !isNonEmptyString(
      observation.authorizationId
    )
  ) {
    return null;
  }

  return (
    authorizationMap.get(
      observation.authorizationId
    ) || null
  );
}

/* =========================================================
   SENSOR / OBSERVATION COMPATIBILITY
   ========================================================= */

function isObservationAllowedForSensor(
  sensorType,
  observationType
) {
  const allowed =
    SENSOR_OBSERVATION_MAP[sensorType];

  if (!Array.isArray(allowed)) {
    return false;
  }

  return allowed.includes(
    observationType
  );
}

/* =========================================================
   OBSERVATION VALIDATION
   ========================================================= */

function validateSessionObservation({
  session,
  incident,
  observation,
  authorization,
  now = new Date(),
}) {
  if (
    !session ||
    typeof session !== "object"
  ) {
    return {
      valid: false,
      error:
        "Fusion session is required.",
    };
  }

  if (
    session.status !==
    SESSION_STATUS.ACTIVE
  ) {
    return {
      valid: false,
      error:
        "Fusion session is not active.",
    };
  }

  if (
    !incident ||
    incident.status !== "ACTIVE"
  ) {
    return {
      valid: false,
      error:
        "Incident must be ACTIVE.",
    };
  }

  if (
    incident.incidentId !==
    session.incidentId
  ) {
    return {
      valid: false,
      error:
        "Incident does not match fusion session.",
    };
  }

  if (
    !observation ||
    typeof observation !== "object"
  ) {
    return {
      valid: false,
      error:
        "Observation is required.",
    };
  }

  if (
    !authorization ||
    typeof authorization !== "object"
  ) {
    return {
      valid: false,
      error:
        "Observation authorization was not found.",
    };
  }

  if (
    !session.authorizationIds.includes(
      authorization.authorizationId
    )
  ) {
    return {
      valid: false,
      error:
        "Authorization is not part of this fusion session.",
    };
  }

  if (
    authorization.incidentId !==
    session.incidentId
  ) {
    return {
      valid: false,
      error:
        "Authorization incident mismatch.",
    };
  }

  if (
    !isAuthorizationActive(
      authorization,
      now
    )
  ) {
    return {
      valid: false,
      error:
        "Observation authorization is not active.",
    };
  }

  if (
    observation.sensorType !==
    authorization.sensorType
  ) {
    return {
      valid: false,
      error:
        "Observation sensor type does not match authorization.",
    };
  }

  if (
    !isNonEmptyString(
      observation.observationType
    )
  ) {
    return {
      valid: false,
      error:
        "observationType is required.",
    };
  }

  if (
    !isObservationAllowedForSensor(
      authorization.sensorType,
      observation.observationType
    )
  ) {
    return {
      valid: false,
      error:
        "Observation type is not permitted for this sensor.",
    };
  }

  if (
    !isFiniteNumber(
      observation.confidence
    ) ||
    observation.confidence < 0 ||
    observation.confidence > 1
  ) {
    return {
      valid: false,
      error:
        "Observation confidence must be between 0 and 1.",
    };
  }

  if (
    !observation.location ||
    typeof observation.location !==
      "object"
  ) {
    return {
      valid: false,
      error:
        "Observation location is required.",
    };
  }

  const {
    latitude,
    longitude,
  } = observation.location;

  if (
    !isValidCoordinate(
      latitude,
      longitude
    )
  ) {
    return {
      valid: false,
      error:
        "Observation coordinates are invalid.",
    };
  }

  if (
    !isCoordinateWithinAuthorization(
      authorization,
      latitude,
      longitude
    )
  ) {
    return {
      valid: false,
      error:
        "Observation is outside its authorized geographic boundary.",
    };
  }

  const observationTime =
    parseDate(observation.timestamp);

  if (!observationTime) {
    return {
      valid: false,
      error:
        "Observation timestamp is invalid.",
    };
  }

  const nowDate = parseDate(now);

  if (!nowDate) {
    return {
      valid: false,
      error:
        "Current validation time is invalid.",
    };
  }

  const ageSeconds =
    (
      nowDate.getTime() -
      observationTime.getTime()
    ) / 1000;

  if (
    ageSeconds >
    SESSION_CONFIG
      .maximumObservationAgeSeconds
  ) {
    return {
      valid: false,
      error:
        "Observation is too old for live fusion.",
    };
  }

  if (
    ageSeconds <
    -SESSION_CONFIG
      .maximumFutureObservationSeconds
  ) {
    return {
      valid: false,
      error:
        "Observation timestamp is too far in the future.",
    };
  }

  if (
    observation.summary !==
      undefined &&
    observation.summary !== null &&
    !isNonEmptyString(
      observation.summary
    )
  ) {
    return {
      valid: false,
      error:
        "summary must be a non-empty string when provided.",
    };
  }

  return {
    valid: true,
  };
}

/* =========================================================
   NORMALIZE OBSERVATION
   ========================================================= */

function normalizeSessionObservation(
  observation,
  authorization
) {
  return {
    observationId:
      isNonEmptyString(
        observation.observationId
      )
        ? observation.observationId.trim()
        : createId("GX_OBS"),

    authorizationId:
      authorization.authorizationId,

    sensorType:
      authorization.sensorType,

    observationType:
      observation.observationType,

    confidence:
      observation.confidence,

    location: {
      latitude:
        observation.location.latitude,

      longitude:
        observation.location.longitude,
    },

    timestamp:
      new Date(
        observation.timestamp
      ).toISOString(),

    summary:
      safeText(observation.summary),

    metadata:
      sanitizeMetadata(
        observation.metadata
      ),
  };
}

/* =========================================================
   CONFIDENCE FUSION
   ========================================================= */

function calculateCombinedConfidence(
  observations
) {
  if (
    !Array.isArray(observations) ||
    observations.length === 0
  ) {
    return 0;
  }

  const total =
    observations.reduce(
      (sum, observation) =>
        sum + observation.confidence,
      0
    );

  const average =
    total / observations.length;

  return Number(
    average.toFixed(4)
  );
}

/* =========================================================
   MULTI-SENSOR SUMMARY
   ========================================================= */

function buildMultiSensorSummary(
  observations
) {
  const bySensor = {};
  const byObservationType = {};

  for (const observation of observations) {
    bySensor[
      observation.sensorType
    ] =
      (
        bySensor[
          observation.sensorType
        ] || 0
      ) + 1;

    byObservationType[
      observation.observationType
    ] =
      (
        byObservationType[
          observation.observationType
        ] || 0
      ) + 1;
  }

  return {
    totalObservations:
      observations.length,

    sensorCount:
      Object.keys(bySensor).length,

    bySensor,

    byObservationType,
  };
}

/* =========================================================
   OUTPUT SELECTION
   ========================================================= */

function getCandidateOutputs(
  observationType
) {
  switch (observationType) {
    case OBSERVATION_TYPES
      .VISUAL_DETECTION:

      return [
        ALLOWED_OUTPUTS
          .DETECTION_SUMMARY,

        ALLOWED_OUTPUTS
          .EMERGENCY_MAP,
      ];

    case OBSERVATION_TYPES
      .THERMAL_DETECTION:

      return [
        ALLOWED_OUTPUTS
          .THERMAL_ALERT,

        ALLOWED_OUTPUTS
          .EMERGENCY_MAP,
      ];

    case OBSERVATION_TYPES
      .NIGHT_VISION_DETECTION:

      return [
        ALLOWED_OUTPUTS
          .DETECTION_SUMMARY,

        ALLOWED_OUTPUTS
          .EMERGENCY_MAP,
      ];

    case OBSERVATION_TYPES
      .WAMI_CONTEXT:

      return [
        ALLOWED_OUTPUTS
          .DETECTION_SUMMARY,

        ALLOWED_OUTPUTS
          .EMERGENCY_MAP,
      ];

    case OBSERVATION_TYPES
      .DRONE_TELEMETRY:

      return [
        ALLOWED_OUTPUTS
          .SENSOR_HEALTH,
      ];

    case OBSERVATION_TYPES
      .SAR_CONTEXT:

      return [
        ALLOWED_OUTPUTS
          .TERRAIN_CONTEXT,
      ];

    case OBSERVATION_TYPES
      .WEATHER_CONTEXT:

      return [
        ALLOWED_OUTPUTS
          .WEATHER_CONTEXT,
      ];

    case OBSERVATION_TYPES
      .TERRAIN_CONTEXT:

      return [
        ALLOWED_OUTPUTS
          .TERRAIN_CONTEXT,
      ];

    default:
      return [];
  }
}

function determineSessionOutputs(
  observations,
  authorizationMap
) {
  const outputs = new Set();

  for (const observation of observations) {
    const authorization =
      authorizationMap.get(
        observation.authorizationId
      );

    if (!authorization) {
      continue;
    }

    const candidates =
      getCandidateOutputs(
        observation.observationType
      );

    for (const output of candidates) {
      if (
        isOutputAllowed(
          authorization,
          output
        )
      ) {
        outputs.add(output);
      }
    }
  }

  return Array.from(outputs);
}

/* =========================================================
   MULTI-SENSOR FUSION
   ========================================================= */

function fuseSessionObservations({
  session,
  incident,
  authorizations,
  observations,
  now = new Date(),
}) {
  const incidentValidation =
    validateIncident(incident);

  if (!incidentValidation.valid) {
    return {
      success: false,
      error:
        incidentValidation.error,
    };
  }

  if (
    !session ||
    typeof session !== "object"
  ) {
    return {
      success: false,
      error:
        "Fusion session is required.",
    };
  }

  if (
    session.status !==
    SESSION_STATUS.ACTIVE
  ) {
    return {
      success: false,
      error:
        "Fusion session is not active.",
    };
  }

  if (
    session.incidentId !==
    incident.incidentId
  ) {
    return {
      success: false,
      error:
        "Fusion session does not belong to this incident.",
    };
  }

  const authorizationValidation =
    validateAuthorizationSet({
      incident,
      authorizations,
      now,
    });

  if (!authorizationValidation.valid) {
    return {
      success: false,
      error:
        authorizationValidation.error,
    };
  }

  const authorizationMap =
    createAuthorizationMap(
      authorizations
    );

  for (
    const authorizationId
    of session.authorizationIds
  ) {
    if (
      !authorizationMap.has(
        authorizationId
      )
    ) {
      return {
        success: false,
        error:
          "A fusion-session authorization is missing.",
      };
    }
  }

  if (!Array.isArray(observations)) {
    return {
      success: false,
      error:
        "observations must be an array.",
    };
  }

  if (observations.length === 0) {
    return {
      success: false,
      error:
        "At least one observation is required.",
    };
  }

  if (
    observations.length >
    SESSION_CONFIG.maximumObservations
  ) {
    return {
      success: false,
      error:
        "Fusion observation limit exceeded.",
    };
  }

  const normalizedObservations = [];

  for (
    let index = 0;
    index < observations.length;
    index += 1
  ) {
    const observation =
      observations[index];

    const authorization =
      findAuthorizationForObservation(
        observation,
        authorizationMap
      );

    const validation =
      validateSessionObservation({
        session,
        incident,
        observation,
        authorization,
        now,
      });

    /*
     * FAIL CLOSED:
     * Reject the entire fusion batch if
     * any single observation is invalid.
     */
    if (!validation.valid) {
      return {
        success: false,

        error:
          `Observation ${index + 1}: ` +
          validation.error,
      };
    }

    normalizedObservations.push(
      normalizeSessionObservation(
        observation,
        authorization
      )
    );
  }

  const confidence =
    calculateCombinedConfidence(
      normalizedObservations
    );

  const summary =
    buildMultiSensorSummary(
      normalizedObservations
    );

  const outputs =
    determineSessionOutputs(
      normalizedObservations,
      authorizationMap
    );

  const fusionResult = {
    fusionId:
      createId(
        "GX_MULTI_FUSION"
      ),

    fusionVersion:
      SESSION_CONFIG.version,

    sessionId:
      session.sessionId,

    incidentId:
      incident.incidentId,

    confidence,

    summary,

    outputs,

    observations:
      normalizedObservations,

    generatedAt:
      new Date(now).toISOString(),

    privacyControls: {
      emergencyScoped: true,

      independentSensorAuthorizationRequired:
        true,

      geographicBoundaryEnforced:
        true,

      outputPermissionEnforced:
        true,

      faceRecognitionEnabled:
        false,

      persistentIdentityTrackingEnabled:
        false,

      unrestrictedBackgroundSurveillanceEnabled:
        false,
    },
  };

  const primaryAuthorization =
    authorizations[0];

  const auditEvent =
    createSessionAuditEvent({
      action:
        "MULTI_SENSOR_FUSION_CREATED",

      authorization:
        primaryAuthorization,

      success: true,

      sessionId:
        session.sessionId,

      fusionId:
        fusionResult.fusionId,
    });

  return {
    success: true,
    fusionResult,
    auditEvent,
  };
}

/* =========================================================
   CLOSE FUSION SESSION
   ========================================================= */

function closeFusionSession({
  session,
  closedBy,
  authorization = null,
  now = new Date(),
}) {
  if (
    !session ||
    typeof session !== "object"
  ) {
    return {
      success: false,
      error:
        "Fusion session is required.",
    };
  }

  if (
    session.status !==
    SESSION_STATUS.ACTIVE
  ) {
    return {
      success: false,
      error:
        "Fusion session is not active.",
    };
  }

  if (!isNonEmptyString(closedBy)) {
    return {
      success: false,
      error:
        "closedBy is required.",
    };
  }

  const closedSession = {
    ...session,

    status:
      SESSION_STATUS.CLOSED,

    closedBy:
      closedBy.trim(),

    closedAt:
      new Date(now).toISOString(),
  };

  const auditEvent =
    createSessionAuditEvent({
      action:
        "FUSION_SESSION_CLOSED",

      authorization,

      success: true,

      sessionId:
        session.sessionId,
    });

  return {
    success: true,

    session:
      closedSession,

    auditEvent,
  };
}

/* =========================================================
   STATUS
   ========================================================= */

function getFusionSessionStatus() {
  return {
    name:
      "Guardian X Multi-Sensor Fusion Session",

    version:
      SESSION_CONFIG.version,

    failClosed: true,

    multiSensorFusion: true,

    independentSensorAuthorizationRequired:
      true,

    geographicBoundaryEnforced:
      true,

    outputPermissionEnforced:
      true,

    hardwareActivation:
      false,

    faceRecognitionEnabled:
      false,

    persistentIdentityTrackingEnabled:
      false,

    unrestrictedBackgroundSurveillanceEnabled:
      false,
  };
}

/* =========================================================
   EXPORTS
   ========================================================= */

module.exports = {
  SESSION_CONFIG,
  SESSION_STATUS,

  validateAuthorizationSet,

  createFusionSession,

  validateSessionObservation,

  normalizeSessionObservation,

  calculateCombinedConfidence,

  buildMultiSensorSummary,

  determineSessionOutputs,

  fuseSessionObservations,

  closeFusionSession,

  getFusionSessionStatus,
};
