"use strict";

/*
 * Guardian X — Fusion Engine
 *
 * Purpose:
 *   Receives already-authorized sensor observations and combines them
 *   into a bounded emergency-context result.
 *
 * Security principles:
 *   - Requires a valid sensor authorization
 *   - Requires an ACTIVE authorization window
 *   - Enforces geographic boundaries
 *   - Enforces allowed outputs
 *   - No direct hardware activation
 *   - No face recognition
 *   - No unrestricted identity tracking
 *   - No continuous/background surveillance
 *   - Designed for emergency-scoped use
 */

const crypto = require("crypto");

const {
  SENSOR_TYPES,
  ALLOWED_OUTPUTS,
  isAuthorizationActive,
  isCoordinateWithinAuthorization,
  isOutputAllowed,
  buildAuditEvent,
} = require("./sensorPolicy");

/* =========================================================
   FUSION CONFIGURATION
   ========================================================= */

const FUSION_CONFIG = Object.freeze({
  minimumConfidence: 0,
  maximumConfidence: 1,

  maximumObservationsPerFusion: 100,

  maximumObservationAgeSeconds: 120,

  maximumTextLength: 500,

  supportedFusionVersion: "1.0.0",
});

/* =========================================================
   OBSERVATION TYPES
   ========================================================= */

const OBSERVATION_TYPES = Object.freeze({
  VISUAL_DETECTION: "VISUAL_DETECTION",
  THERMAL_DETECTION: "THERMAL_DETECTION",
  NIGHT_VISION_DETECTION: "NIGHT_VISION_DETECTION",
  WAMI_CONTEXT: "WAMI_CONTEXT",
  DRONE_TELEMETRY: "DRONE_TELEMETRY",
  SAR_CONTEXT: "SAR_CONTEXT",
  WEATHER_CONTEXT: "WEATHER_CONTEXT",
  TERRAIN_CONTEXT: "TERRAIN_CONTEXT",
});

/* =========================================================
   SENSOR → OBSERVATION MAPPING
   ========================================================= */

const SENSOR_OBSERVATION_MAP = Object.freeze({
  [SENSOR_TYPES.DRONE_RGB]: [
    OBSERVATION_TYPES.VISUAL_DETECTION,
  ],

  [SENSOR_TYPES.DRONE_THERMAL]: [
    OBSERVATION_TYPES.THERMAL_DETECTION,
  ],

  [SENSOR_TYPES.DRONE_NIGHT_VISION]: [
    OBSERVATION_TYPES.NIGHT_VISION_DETECTION,
  ],

  [SENSOR_TYPES.DRONE_WAMI]: [
    OBSERVATION_TYPES.WAMI_CONTEXT,
  ],

  [SENSOR_TYPES.DRONE_TELEMETRY]: [
    OBSERVATION_TYPES.DRONE_TELEMETRY,
  ],

  [SENSOR_TYPES.SENTINEL_1]: [
    OBSERVATION_TYPES.SAR_CONTEXT,
  ],

  [SENSOR_TYPES.WEATHER]: [
    OBSERVATION_TYPES.WEATHER_CONTEXT,
  ],

  [SENSOR_TYPES.TERRAIN]: [
    OBSERVATION_TYPES.TERRAIN_CONTEXT,
  ],
});

/* =========================================================
   BASIC HELPERS
   ========================================================= */

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function safeText(value) {
  if (!isNonEmptyString(value)) {
    return null;
  }

  return value.trim().slice(0, FUSION_CONFIG.maximumTextLength);
}

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function isValidConfidence(value) {
  return (
    isFiniteNumber(value) &&
    value >= FUSION_CONFIG.minimumConfidence &&
    value <= FUSION_CONFIG.maximumConfidence
  );
}

function isValidLatitude(value) {
  return isFiniteNumber(value) && value >= -90 && value <= 90;
}

function isValidLongitude(value) {
  return isFiniteNumber(value) && value >= -180 && value <= 180;
}

function isValidCoordinate(latitude, longitude) {
  return isValidLatitude(latitude) && isValidLongitude(longitude);
}

function parseDate(value) {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date;
}

function generateFusionId() {
  return `fusion_${crypto.randomUUID()}`;
}

function generateObservationId() {
  return `obs_${crypto.randomUUID()}`;
}

/* =========================================================
   SENSOR / OBSERVATION COMPATIBILITY
   ========================================================= */

function isObservationAllowedForSensor(sensorType, observationType) {
  const allowed = SENSOR_OBSERVATION_MAP[sensorType];

  if (!Array.isArray(allowed)) {
    return false;
  }

  return allowed.includes(observationType);
}

/* =========================================================
   OBSERVATION VALIDATION
   ========================================================= */

function validateObservation(observation, authorization) {
  const errors = [];

  if (!observation || typeof observation !== "object") {
    return {
      valid: false,
      errors: ["Observation is required."],
    };
  }

  if (!authorization || typeof authorization !== "object") {
    return {
      valid: false,
      errors: ["Authorization is required."],
    };
  }

  if (!isNonEmptyString(observation.sensorType)) {
    errors.push("sensorType is required.");
  }

  if (observation.sensorType !== authorization.sensorType) {
    errors.push(
      "Observation sensor type does not match the authorization."
    );
  }

  if (!isNonEmptyString(observation.observationType)) {
    errors.push("observationType is required.");
  }

  if (
    observation.sensorType &&
    observation.observationType &&
    !isObservationAllowedForSensor(
      observation.sensorType,
      observation.observationType
    )
  ) {
    errors.push(
      "Observation type is not permitted for this sensor."
    );
  }

  if (!isValidConfidence(observation.confidence)) {
    errors.push("confidence must be between 0 and 1.");
  }

  if (!observation.location || typeof observation.location !== "object") {
    errors.push("Observation location is required.");
  } else {
    const { latitude, longitude } = observation.location;

    if (!isValidCoordinate(latitude, longitude)) {
      errors.push("Observation coordinates are invalid.");
    } else if (
      !isCoordinateWithinAuthorization(
        authorization,
        latitude,
        longitude
      )
    ) {
      errors.push(
        "Observation is outside the authorized geographic boundary."
      );
    }
  }

  const timestamp = parseDate(observation.timestamp);

  if (!timestamp) {
    errors.push("Observation timestamp is invalid.");
  } else {
    const ageMs = Date.now() - timestamp.getTime();
    const maximumAgeMs =
      FUSION_CONFIG.maximumObservationAgeSeconds * 1000;

    if (ageMs > maximumAgeMs) {
      errors.push("Observation is too old for live fusion.");
    }

    if (ageMs < -30000) {
      errors.push("Observation timestamp is in the future.");
    }
  }

  if (
    observation.summary !== undefined &&
    observation.summary !== null &&
    !isNonEmptyString(observation.summary)
  ) {
    errors.push("summary must be a non-empty string when provided.");
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/* =========================================================
   NORMALIZE OBSERVATION
   ========================================================= */

function normalizeObservation(observation) {
  return {
    observationId:
      observation.observationId || generateObservationId(),

    sensorType: observation.sensorType,

    observationType: observation.observationType,

    confidence: observation.confidence,

    location: {
      latitude: observation.location.latitude,
      longitude: observation.location.longitude,
    },

    timestamp: new Date(observation.timestamp).toISOString(),

    summary: safeText(observation.summary),

    metadata:
      observation.metadata &&
      typeof observation.metadata === "object"
        ? sanitizeMetadata(observation.metadata)
        : {},
  };
}

/* =========================================================
   SAFE METADATA
   ========================================================= */

function sanitizeMetadata(metadata) {
  const safe = {};

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

  for (const key of allowedKeys) {
    if (
      Object.prototype.hasOwnProperty.call(metadata, key)
    ) {
      safe[key] = metadata[key];
    }
  }

  return safe;
}

/* =========================================================
   CONFIDENCE FUSION
   ========================================================= */

function calculateFusionConfidence(observations) {
  if (!Array.isArray(observations) || observations.length === 0) {
    return 0;
  }

  const validConfidences = observations
    .map((item) => item.confidence)
    .filter(isValidConfidence);

  if (validConfidences.length === 0) {
    return 0;
  }

  const total = validConfidences.reduce(
    (sum, value) => sum + value,
    0
  );

  const average = total / validConfidences.length;

  return Number(average.toFixed(4));
}

/* =========================================================
   FUSION SUMMARY
   ========================================================= */

function buildFusionSummary(observations) {
  const summary = {
    totalObservations: observations.length,

    rgbDetections: 0,
    thermalDetections: 0,
    nightVisionDetections: 0,
    wamiContexts: 0,
    telemetryUpdates: 0,
    sarContexts: 0,
    weatherContexts: 0,
    terrainContexts: 0,
  };

  for (const observation of observations) {
    switch (observation.observationType) {
      case OBSERVATION_TYPES.VISUAL_DETECTION:
        summary.rgbDetections += 1;
        break;

      case OBSERVATION_TYPES.THERMAL_DETECTION:
        summary.thermalDetections += 1;
        break;

      case OBSERVATION_TYPES.NIGHT_VISION_DETECTION:
        summary.nightVisionDetections += 1;
        break;

      case OBSERVATION_TYPES.WAMI_CONTEXT:
        summary.wamiContexts += 1;
        break;

      case OBSERVATION_TYPES.DRONE_TELEMETRY:
        summary.telemetryUpdates += 1;
        break;

      case OBSERVATION_TYPES.SAR_CONTEXT:
        summary.sarContexts += 1;
        break;

      case OBSERVATION_TYPES.WEATHER_CONTEXT:
        summary.weatherContexts += 1;
        break;

      case OBSERVATION_TYPES.TERRAIN_CONTEXT:
        summary.terrainContexts += 1;
        break;

      default:
        break;
    }
  }

  return summary;
}

/* =========================================================
   OUTPUT SELECTION
   ========================================================= */

function determineOutputs(authorization, observations) {
  const outputs = new Set();

  for (const observation of observations) {
    switch (observation.observationType) {
      case OBSERVATION_TYPES.VISUAL_DETECTION:
      case OBSERVATION_TYPES.NIGHT_VISION_DETECTION:
      case OBSERVATION_TYPES.WAMI_CONTEXT:
        if (
          isOutputAllowed(
            authorization,
            ALLOWED_OUTPUTS.DETECTION_SUMMARY
          )
        ) {
          outputs.add(ALLOWED_OUTPUTS.DETECTION_SUMMARY);
        }

        if (
          isOutputAllowed(
            authorization,
            ALLOWED_OUTPUTS.EMERGENCY_MAP
          )
        ) {
          outputs.add(ALLOWED_OUTPUTS.EMERGENCY_MAP);
        }

        break;

      case OBSERVATION_TYPES.THERMAL_DETECTION:
        if (
          isOutputAllowed(
            authorization,
            ALLOWED_OUTPUTS.THERMAL_ALERT
          )
        ) {
          outputs.add(ALLOWED_OUTPUTS.THERMAL_ALERT);
        }

        if (
          isOutputAllowed(
            authorization,
            ALLOWED_OUTPUTS.EMERGENCY_MAP
          )
        ) {
          outputs.add(ALLOWED_OUTPUTS.EMERGENCY_MAP);
        }

        break;

      case OBSERVATION_TYPES.DRONE_TELEMETRY:
        if (
          isOutputAllowed(
            authorization,
            ALLOWED_OUTPUTS.SENSOR_HEALTH
          )
        ) {
          outputs.add(ALLOWED_OUTPUTS.SENSOR_HEALTH);
        }

        break;

      case OBSERVATION_TYPES.SAR_CONTEXT:
      case OBSERVATION_TYPES.TERRAIN_CONTEXT:
        if (
          isOutputAllowed(
            authorization,
            ALLOWED_OUTPUTS.TERRAIN_CONTEXT
          )
        ) {
          outputs.add(ALLOWED_OUTPUTS.TERRAIN_CONTEXT);
        }

        break;

      case OBSERVATION_TYPES.WEATHER_CONTEXT:
        if (
          isOutputAllowed(
            authorization,
            ALLOWED_OUTPUTS.WEATHER_CONTEXT
          )
        ) {
          outputs.add(ALLOWED_OUTPUTS.WEATHER_CONTEXT);
        }

        break;

      default:
        break;
    }
  }

  return Array.from(outputs);
}

/* =========================================================
   FUSION ENGINE
   ========================================================= */

function fuseObservations({
  authorization,
  incident,
  observations,
  now = new Date(),
}) {
  /*
   * FAIL CLOSED.
   *
   * Fusion does not proceed unless authorization,
   * incident, timing, geography and sensor compatibility
   * all pass.
   */

  if (!authorization || typeof authorization !== "object") {
    return {
      success: false,
      errors: ["Authorization is required."],
    };
  }

  if (!incident || typeof incident !== "object") {
    return {
      success: false,
      errors: ["Incident is required."],
    };
  }

  if (incident.status !== "ACTIVE") {
    return {
      success: false,
      errors: ["Incident must be ACTIVE."],
    };
  }

  if (incident.incidentId !== authorization.incidentId) {
    return {
      success: false,
      errors: [
        "Authorization does not belong to this incident.",
      ],
    };
  }

  if (!isAuthorizationActive(authorization, now)) {
    return {
      success: false,
      errors: ["Sensor authorization is not active."],
    };
  }

  if (!Array.isArray(observations)) {
    return {
      success: false,
      errors: ["observations must be an array."],
    };
  }

  if (observations.length === 0) {
    return {
      success: false,
      errors: ["At least one observation is required."],
    };
  }

  if (
    observations.length >
    FUSION_CONFIG.maximumObservationsPerFusion
  ) {
    return {
      success: false,
      errors: [
        `Fusion request exceeds the ${FUSION_CONFIG.maximumObservationsPerFusion}-observation limit.`,
      ],
    };
  }

  const normalizedObservations = [];
  const validationErrors = [];

  observations.forEach((observation, index) => {
    const validation = validateObservation(
      observation,
      authorization
    );

    if (!validation.valid) {
      for (const error of validation.errors) {
        validationErrors.push(
          `Observation ${index + 1}: ${error}`
        );
      }

      return;
    }

    normalizedObservations.push(
      normalizeObservation(observation)
    );
  });

  /*
   * Fail the entire batch rather than silently processing
   * only part of an invalid sensor batch.
   */
  if (validationErrors.length > 0) {
    return {
      success: false,
      errors: validationErrors,
    };
  }

  const confidence = calculateFusionConfidence(
    normalizedObservations
  );

  const outputs = determineOutputs(
    authorization,
    normalizedObservations
  );

  const fusionResult = {
    fusionId: generateFusionId(),

    fusionVersion:
      FUSION_CONFIG.supportedFusionVersion,

    incidentId: incident.incidentId,

    authorizationId:
      authorization.authorizationId,

    sensorType:
      authorization.sensorType,

    purpose:
      authorization.purpose,

    confidence,

    summary:
      buildFusionSummary(normalizedObservations),

    outputs,

    observations:
      normalizedObservations,

    generatedAt:
      new Date(now).toISOString(),

    geographicBoundary:
      authorization.geographicBoundary,

    expiresAt:
      authorization.expiresAt,

    privacyControls: {
      emergencyScoped: true,
      geographicBoundaryEnforced: true,
      authorizationRequired: true,
      faceRecognitionEnabled: false,
      persistentIdentityTrackingEnabled: false,
      unrestrictedBackgroundSurveillanceEnabled: false,
    },
  };

  const auditEvent = buildAuditEvent(
    "FUSION_RESULT_CREATED",
    authorization,
    true,
    null
  );

  return {
    success: true,
    fusionResult,
    auditEvent,
  };
}

/* =========================================================
   ENGINE STATUS
   ========================================================= */

function getFusionEngineStatus() {
  return {
    name: "Guardian X Fusion Engine",

    version:
      FUSION_CONFIG.supportedFusionVersion,

    failClosed: true,

    hardwareActivation: false,

    authorizationRequired: true,

    geographicBoundaryEnforced: true,

    faceRecognitionEnabled: false,

    persistentIdentityTrackingEnabled: false,

    sensors:
      Object.keys(SENSOR_OBSERVATION_MAP),

    observationTypes:
      Object.values(OBSERVATION_TYPES),
  };
}

/* =========================================================
   EXPORTS
   ========================================================= */

module.exports = {
  FUSION_CONFIG,
  OBSERVATION_TYPES,
  SENSOR_OBSERVATION_MAP,

  validateObservation,
  normalizeObservation,

  calculateFusionConfidence,
  buildFusionSummary,
  determineOutputs,

  fuseObservations,

  getFusionEngineStatus,
};
