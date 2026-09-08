"use strict";

const crypto = require("crypto");

const {
  isAuthorizationActive,
  isCoordinateWithinAuthorization,
  isOutputAllowed,
  buildAuditEvent,
} = require("./sensorPolicy");

const {
  OBSERVATION_TYPES,
  SENSOR_OBSERVATION_MAP,
} = require("./fusionEngine");

const SESSION_CONFIG = Object.freeze({
  version: "1.0.0",
  maxAuthorizations: 20,
  maxObservations: 200,
  maxObservationAgeSeconds: 120,
  maxFutureObservationSeconds: 30,
  maxSummaryLength: 500,
});

const SESSION_STATUS = Object.freeze({
  ACTIVE: "ACTIVE",
  CLOSED: "CLOSED",
});

function createId(prefix) {
  return `${prefix}-${crypto.randomUUID()}`;
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function isValidNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function isValidCoordinate(latitude, longitude) {
  return (
    isValidNumber(latitude) &&
    isValidNumber(longitude) &&
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

function sanitizeSummary(value) {
  if (!isNonEmptyString(value)) {
    return null;
  }

  return value.trim().slice(0, SESSION_CONFIG.maxSummaryLength);
}

function sanitizeMetadata(metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
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

  const sanitized = {};

  for (const key of allowedKeys) {
    if (Object.prototype.hasOwnProperty.call(metadata, key)) {
      sanitized[key] = metadata[key];
    }
  }

  return sanitized;
}

function validateIncident(incident) {
  if (!incident || typeof incident !== "object") {
    return {
      valid: false,
      reason: "Incident is required.",
    };
  }

  if (!isNonEmptyString(incident.incidentId)) {
    return {
      valid: false,
      reason: "Incident ID is required.",
    };
  }

  if (incident.status !== "ACTIVE") {
    return {
      valid: false,
      reason: "Incident must be ACTIVE.",
    };
  }

  return {
    valid: true,
  };
}

function validateAuthorizationSet({
  incident,
  authorizations,
  now = new Date(),
}) {
  const incidentValidation = validateIncident(incident);

  if (!incidentValidation.valid) {
    return incidentValidation;
  }

  if (!Array.isArray(authorizations) || authorizations.length === 0) {
    return {
      valid: false,
      reason: "At least one sensor authorization is required.",
    };
  }

  if (authorizations.length > SESSION_CONFIG.maxAuthorizations) {
    return {
      valid: false,
      reason: "Too many sensor authorizations.",
    };
  }

  const authorizationIds = new Set();

  for (const authorization of authorizations) {
    if (!authorization || typeof authorization !== "object") {
      return {
        valid: false,
        reason: "Invalid sensor authorization.",
      };
    }

    if (!isNonEmptyString(authorization.authorizationId)) {
      return {
        valid: false,
        reason: "Authorization ID is required.",
      };
    }

    if (authorizationIds.has(authorization.authorizationId)) {
      return {
        valid: false,
        reason: "Duplicate authorization ID.",
      };
    }

    authorizationIds.add(authorization.authorizationId);

    if (authorization.incidentId !== incident.incidentId) {
      return {
        valid: false,
        reason: "Authorization does not belong to this incident.",
      };
    }

    if (!isAuthorizationActive(authorization, now)) {
      return {
        valid: false,
        reason: "Sensor authorization is not active.",
      };
    }
  }

  return {
    valid: true,
  };
}

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

  const validation = validateAuthorizationSet({
    incident,
    authorizations,
    now,
  });

  if (!validation.valid) {
    return {
      success: false,
      error: validation.reason,
    };
  }

  const session = {
    sessionId: createId("GX-FUSION"),
    version: SESSION_CONFIG.version,
    incidentId: incident.incidentId,
    status: SESSION_STATUS.ACTIVE,
    createdBy: createdBy.trim(),
    createdAt: new Date(now).toISOString(),
    authorizationIds: authorizations.map(
      (authorization) => authorization.authorizationId
    ),
    sensorTypes: [
      ...new Set(
        authorizations.map((authorization) => authorization.sensorType)
      ),
    ],
    privacyControls: {
      emergencyScoped: true,
      independentSensorAuthorizationRequired: true,
      geographicBoundaryEnforced: true,
      faceRecognitionEnabled: false,
      persistentIdentityTrackingEnabled: false,
      unrestrictedBackgroundSurveillanceEnabled: false,
    },
  };

  return {
    success: true,
    session,
    auditEvent: buildAuditEvent({
      event: "FUSION_SESSION_CREATED",
      incidentId: incident.incidentId,
      authorizationId: null,
      sensorType: null,
      success: true,
      details: {
        sessionId: session.sessionId,
        createdBy: session.createdBy,
        authorizationCount: session.authorizationIds.length,
        sensorTypes: session.sensorTypes,
      },
    }),
  };
}

function findAuthorizationForObservation(
  observation,
  authorizationMap
) {
  if (
    observation &&
    isNonEmptyString(observation.authorizationId)
  ) {
    return authorizationMap.get(observation.authorizationId) || null;
  }

  return null;
}

function validateSessionObservation({
  session,
  incident,
  observation,
  authorization,
  now = new Date(),
}) {
  if (!session || session.status !== SESSION_STATUS.ACTIVE) {
    return {
      valid: false,
      reason: "Fusion session is not active.",
    };
  }

  if (!observation || typeof observation !== "object") {
    return {
      valid: false,
      reason: "Observation is required.",
    };
  }

  if (!authorization) {
    return {
      valid: false,
      reason: "Observation authorization was not found.",
    };
  }

  if (
    !session.authorizationIds.includes(
      authorization.authorizationId
    )
  ) {
    return {
      valid: false,
      reason: "Authorization is not part of this fusion session.",
    };
  }

  if (
    incident.incidentId !== session.incidentId ||
    authorization.incidentId !== session.incidentId
  ) {
    return {
      valid: false,
      reason: "Incident mismatch.",
    };
  }

  if (!isAuthorizationActive(authorization, now)) {
    return {
      valid: false,
      reason: "Observation authorization is not active.",
    };
  }

  if (observation.sensorType !== authorization.sensorType) {
    return {
      valid: false,
      reason: "Observation sensor does not match authorization.",
    };
  }

  const expectedObservationType =
    SENSOR_OBSERVATION_MAP[authorization.sensorType];

  if (!expectedObservationType) {
    return {
      valid: false,
      reason: "Sensor type is not supported by the fusion engine.",
    };
  }

  if (observation.type !== expectedObservationType) {
    return {
      valid: false,
      reason: "Observation type does not match sensor type.",
    };
  }

  if (
    !isValidNumber(observation.confidence) ||
    observation.confidence < 0 ||
    observation.confidence > 1
  ) {
    return {
      valid: false,
      reason: "Observation confidence must be between 0 and 1.",
    };
  }

  if (
    !observation.location ||
    !isValidCoordinate(
      observation.location.latitude,
      observation.location.longitude
    )
  ) {
    return {
      valid: false,
      reason: "Observation location is invalid.",
    };
  }

  if (
    !isCoordinateWithinAuthorization(
      authorization,
      observation.location.latitude,
      observation.location.longitude
    )
  ) {
    return {
      valid: false,
      reason: "Observation is outside its authorized geographic boundary.",
    };
  }

  const observationTime = parseDate(observation.timestamp);

  if (!observationTime) {
    return {
      valid: false,
      reason: "Observation timestamp is invalid.",
    };
  }

  const nowDate = new Date(now);
  const ageSeconds =
    (nowDate.getTime() - observationTime.getTime()) / 1000;

  if (ageSeconds > SESSION_CONFIG.maxObservationAgeSeconds) {
    return {
      valid: false,
      reason: "Observation is too old.",
    };
  }

  if (ageSeconds < -SESSION_CONFIG.maxFutureObservationSeconds) {
    return {
      valid: false,
      reason: "Observation timestamp is too far in the future.",
    };
  }

  return {
    valid: true,
  };
}

function normalizeSessionObservation(
  observation,
  authorization
) {
  return {
    observationId: isNonEmptyString(observation.observationId)
      ? observation.observationId.trim()
      : createId("GX-OBS"),

    authorizationId: authorization.authorizationId,
    sensorType: authorization.sensorType,
    type: observation.type,
    confidence: observation.confidence,

    location: {
      latitude: observation.location.latitude,
      longitude: observation.location.longitude,
    },

    timestamp: new Date(observation.timestamp).toISOString(),

    summary: sanitizeSummary(observation.summary),

    metadata: sanitizeMetadata(observation.metadata),
  };
}

function calculateCombinedConfidence(observations) {
  if (!Array.isArray(observations) || observations.length === 0) {
    return 0;
  }

  const total = observations.reduce(
    (sum, observation) => sum + observation.confidence,
    0
  );

  return Number((total / observations.length).toFixed(4));
}

function buildMultiSensorSummary(observations) {
  const bySensor = {};
  const byType = {};

  for (const observation of observations) {
    bySensor[observation.sensorType] =
      (bySensor[observation.sensorType] || 0) + 1;

    byType[observation.type] =
      (byType[observation.type] || 0) + 1;
  }

  return {
    totalObservations: observations.length,
    sensorCount: Object.keys(bySensor).length,
    bySensor,
    byType,
  };
}

function determineSessionOutputs(
  observations,
  authorizationMap
) {
  const outputs = new Set();

  for (const observation of observations) {
    const authorization = authorizationMap.get(
      observation.authorizationId
    );

    if (!authorization) {
      continue;
    }

    const candidates = [];

    switch (observation.type) {
      case OBSERVATION_TYPES.THERMAL_DETECTION:
        candidates.push(
          "THERMAL_ALERT",
          "DETECTION_SUMMARY",
          "EMERGENCY_MAP"
        );
        break;

      case OBSERVATION_TYPES.VISUAL_DETECTION:
      case OBSERVATION_TYPES.NIGHT_VISION_DETECTION:
        candidates.push(
          "DETECTION_SUMMARY",
          "EMERGENCY_MAP"
        );
        break;

      case OBSERVATION_TYPES.WAMI_CONTEXT:
        candidates.push(
          "SEARCH_AREA_STATUS",
          "EMERGENCY_MAP"
        );
        break;

      case OBSERVATION_TYPES.DRONE_TELEMETRY:
        candidates.push(
          "SENSOR_HEALTH",
          "EMERGENCY_MAP"
        );
        break;

      case OBSERVATION_TYPES.SAR_CONTEXT:
        candidates.push(
          "SEARCH_AREA_STATUS",
          "ROUTE_HAZARD",
          "EMERGENCY_MAP"
        );
        break;

      case OBSERVATION_TYPES.WEATHER_CONTEXT:
        candidates.push(
          "WEATHER_CONTEXT",
          "ROUTE_HAZARD"
        );
        break;

      case OBSERVATION_TYPES.TERRAIN_CONTEXT:
        candidates.push(
          "TERRAIN_CONTEXT",
          "ROUTE_HAZARD"
        );
        break;

      default:
        break;
    }

    for (const output of candidates) {
      if (isOutputAllowed(authorization, output)) {
        outputs.add(output);
      }
    }
  }

  return [...outputs];
}

function fuseSessionObservations({
  session,
  incident,
  authorizations,
  observations,
  now = new Date(),
}) {
  const incidentValidation = validateIncident(incident);

  if (!incidentValidation.valid) {
    return {
      success: false,
      error: incidentValidation.reason,
    };
  }

  if (!session || session.status !== SESSION_STATUS.ACTIVE) {
    return {
      success: false,
      error: "Fusion session is not active.",
    };
  }

  if (session.incidentId !== incident.incidentId) {
    return {
      success: false,
      error: "Fusion session does not belong to this incident.",
    };
  }

  const authorizationValidation = validateAuthorizationSet({
    incident,
    authorizations,
    now,
  });

  if (!authorizationValidation.valid) {
    return {
      success: false,
      error: authorizationValidation.reason,
    };
  }

  const authorizationMap = new Map(
    authorizations.map((authorization) => [
      authorization.authorizationId,
      authorization,
    ])
  );

  for (const authorizationId of session.authorizationIds) {
    if (!authorizationMap.has(authorizationId)) {
      return {
        success: false,
        error: "A session authorization is missing.",
      };
    }
  }

  if (!Array.isArray(observations) || observations.length === 0) {
    return {
      success: false,
      error: "At least one observation is required.",
    };
  }

  if (observations.length > SESSION_CONFIG.maxObservations) {
    return {
      success: false,
      error: "Too many observations.",
    };
  }

  const normalizedObservations = [];

  for (const observation of observations) {
    const authorization =
      findAuthorizationForObservation(
        observation,
        authorizationMap
      );

    const validation = validateSessionObservation({
      session,
      incident,
      observation,
      authorization,
      now,
    });

    if (!validation.valid) {
      return {
        success: false,
        error: validation.reason,
      };
    }

    normalizedObservations.push(
      normalizeSessionObservation(
        observation,
        authorization
      )
    );
  }

  const result = {
    fusionId: createId("GX-MULTI"),
    sessionId: session.sessionId,
    version: SESSION_CONFIG.version,
    incidentId: incident.incidentId,

    confidence:
      calculateCombinedConfidence(normalizedObservations),

    summary:
      buildMultiSensorSummary(normalizedObservations),

    outputs:
      determineSessionOutputs(
        normalizedObservations,
        authorizationMap
      ),

    observations: normalizedObservations,

    generatedAt: new Date(now).toISOString(),

    privacyControls: {
      emergencyScoped: true,
      independentSensorAuthorizationRequired: true,
      geographicBoundaryEnforced: true,
      faceRecognitionEnabled: false,
      persistentIdentityTrackingEnabled: false,
      unrestrictedBackgroundSurveillanceEnabled: false,
    },
  };

  return {
    success: true,
    result,
    auditEvent: buildAuditEvent({
      event: "MULTI_SENSOR_FUSION_COMPLETED",
      incidentId: incident.incidentId,
      authorizationId: null,
      sensorType: null,
      success: true,
      details: {
        sessionId: session.sessionId,
        fusionId: result.fusionId,
        observationCount:
          normalizedObservations.length,
        sensorCount: result.summary.sensorCount,
        outputs: result.outputs,
      },
    }),
  };
}

function closeFusionSession({
  session,
  closedBy,
  now = new Date(),
}) {
  if (!session || typeof session !== "object") {
    return {
      success: false,
      error: "Fusion session is required.",
    };
  }

  if (session.status !== SESSION_STATUS.ACTIVE) {
    return {
      success: false,
      error: "Fusion session is not active.",
    };
  }

  if (!isNonEmptyString(closedBy)) {
    return {
      success: false,
      error: "closedBy is required.",
    };
  }

  const closedSession = {
    ...session,
    status: SESSION_STATUS.CLOSED,
    closedBy: closedBy.trim(),
    closedAt: new Date(now).toISOString(),
  };

  return {
    success: true,
    session: closedSession,
    auditEvent: buildAuditEvent({
      event: "FUSION_SESSION_CLOSED",
      incidentId: session.incidentId,
      authorizationId: null,
      sensorType: null,
      success: true,
      details: {
        sessionId: session.sessionId,
        closedBy: closedSession.closedBy,
      },
    }),
  };
}

function getFusionSessionStatus() {
  return {
    version: SESSION_CONFIG.version,
    multiSensorFusion: true,
    independentSensorAuthorizationRequired: true,
    geographicBoundaryEnforced: true,
    hardwareActivation: false,
    faceRecognitionEnabled: false,
    persistentIdentityTrackingEnabled: false,
    unrestrictedBackgroundSurveillanceEnabled: false,
  };
}

module.exports = {
  SESSION_CONFIG,
  SESSION_STATUS,
  createFusionSession,
  validateAuthorizationSet,
  validateSessionObservation,
  fuseSessionObservations,
  closeFusionSession,
  getFusionSessionStatus,
};
