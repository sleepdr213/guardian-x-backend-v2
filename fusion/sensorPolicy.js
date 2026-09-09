"use strict";

/*
 * Guardian X — Sensor Authorization Policy
 *
 * Purpose:
 *   Controls whether a sensor request is permitted to enter
 *   the Guardian X Fusion Engine.
 *
 * Security principles:
 *   - Fail closed
 *   - Active incident required
 *   - Explicit purpose required
 *   - Geographic scope required
 *   - Automatic expiration
 *   - Retention must be bounded
 *   - Only approved sensor capabilities may be requested
 *   - Outputs are explicitly restricted
 *
 * IMPORTANT:
 *   This module does NOT activate hardware.
 *   It only evaluates authorization.
 */

const crypto = require("crypto");

/* =========================================================
   SENSOR REGISTRY
   ========================================================= */

const SENSOR_TYPES = Object.freeze({
  DRONE_RGB: "DRONE_RGB",
  DRONE_THERMAL: "DRONE_THERMAL",
  DRONE_NIGHT_VISION: "DRONE_NIGHT_VISION",
  DRONE_WAMI: "DRONE_WAMI",
  DRONE_TELEMETRY: "DRONE_TELEMETRY",

  SENTINEL_1: "SENTINEL_1",
  WEATHER: "WEATHER",
  TERRAIN: "TERRAIN",
});

/*
 * Capabilities are deliberately limited.
 *
 * WAMI remains available as an optional Guardian drone payload.
 * Sentinel-1 is treated as external contextual information.
 */

const SENSOR_CAPABILITIES = Object.freeze({
  [SENSOR_TYPES.DRONE_RGB]: {
    source: "DRONE",
    category: "VISUAL",
    emergencyOnly: true,
    maxDurationMinutes: 30,
  },

  [SENSOR_TYPES.DRONE_THERMAL]: {
    source: "DRONE",
    category: "THERMAL",
    emergencyOnly: true,
    maxDurationMinutes: 30,
  },

  [SENSOR_TYPES.DRONE_NIGHT_VISION]: {
    source: "DRONE",
    category: "VISUAL",
    emergencyOnly: true,
    maxDurationMinutes: 30,
  },

  [SENSOR_TYPES.DRONE_WAMI]: {
    source: "DRONE",
    category: "WIDE_AREA_VISUAL",
    emergencyOnly: true,
    maxDurationMinutes: 20,
  },

  [SENSOR_TYPES.DRONE_TELEMETRY]: {
    source: "DRONE",
    category: "TELEMETRY",
    emergencyOnly: true,
    maxDurationMinutes: 60,
  },

  [SENSOR_TYPES.SENTINEL_1]: {
    source: "REMOTE",
    category: "SAR_CONTEXT",
    emergencyOnly: true,
    maxDurationMinutes: 60,
  },

  [SENSOR_TYPES.WEATHER]: {
    source: "REMOTE",
    category: "ENVIRONMENTAL",
    emergencyOnly: true,
    maxDurationMinutes: 120,
  },

  [SENSOR_TYPES.TERRAIN]: {
    source: "REMOTE",
    category: "ENVIRONMENTAL",
    emergencyOnly: true,
    maxDurationMinutes: 120,
  },
});

/* =========================================================
   ALLOWED PURPOSES
   ========================================================= */

const PURPOSES = Object.freeze({
  SEARCH_AND_RESCUE: "SEARCH_AND_RESCUE",
  ACTIVE_EMERGENCY: "ACTIVE_EMERGENCY",
  MISSING_PERSON: "MISSING_PERSON",
  KIDNAPPING_RESPONSE: "KIDNAPPING_RESPONSE",
  DISASTER_RESPONSE: "DISASTER_RESPONSE",
  HAZARD_ASSESSMENT: "HAZARD_ASSESSMENT",
  EMERGENCY_ROUTE_ASSESSMENT: "EMERGENCY_ROUTE_ASSESSMENT",
});

/* =========================================================
   ALLOWED OUTPUTS
   ========================================================= */

const ALLOWED_OUTPUTS = Object.freeze({
  EMERGENCY_MAP: "EMERGENCY_MAP",
  DETECTION_SUMMARY: "DETECTION_SUMMARY",
  THERMAL_ALERT: "THERMAL_ALERT",
  SEARCH_AREA_STATUS: "SEARCH_AREA_STATUS",
  ROUTE_HAZARD: "ROUTE_HAZARD",
  WEATHER_CONTEXT: "WEATHER_CONTEXT",
  TERRAIN_CONTEXT: "TERRAIN_CONTEXT",
  SENSOR_HEALTH: "SENSOR_HEALTH",
});

/* =========================================================
   CONFIGURATION
   ========================================================= */

const POLICY_CONFIG = Object.freeze({
  minimumDurationMinutes: 1,

  /*
   * Prevents accidental indefinite retention.
   * Specific deployments can make this stricter.
   */
  maximumRetentionHours: 72,

  /*
   * Requests cannot be scheduled indefinitely into the future.
   */
  maximumFutureStartMinutes: 15,

  /*
   * Maximum geographic radius accepted by this policy.
   * This is intentionally conservative.
   */
  maximumRadiusMeters: 5000,
});

/* =========================================================
   BASIC HELPERS
   ========================================================= */

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function isValidDate(value) {
  return value instanceof Date && !Number.isNaN(value.getTime());
}

function parseDate(value) {
  const date = value instanceof Date ? new Date(value) : new Date(value);

  return isValidDate(date) ? date : null;
}

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function isValidLatitude(latitude) {
  return isFiniteNumber(latitude) && latitude >= -90 && latitude <= 90;
}

function isValidLongitude(longitude) {
  return isFiniteNumber(longitude) && longitude >= -180 && longitude <= 180;
}

function isValidCoordinate(latitude, longitude) {
  return isValidLatitude(latitude) && isValidLongitude(longitude);
}

function isKnownSensor(sensorType) {
  return Object.prototype.hasOwnProperty.call(
    SENSOR_CAPABILITIES,
    sensorType
  );
}

function isKnownPurpose(purpose) {
  return Object.values(PURPOSES).includes(purpose);
}

function isKnownOutput(output) {
  return Object.values(ALLOWED_OUTPUTS).includes(output);
}

function generateAuthorizationId() {
  return `sensor_${crypto.randomUUID()}`;
}

/* =========================================================
   GEOBOUNDARY VALIDATION
   ========================================================= */

function validateGeographicBoundary(boundary) {
  if (!boundary || typeof boundary !== "object") {
    return {
      valid: false,
      reason: "Geographic boundary is required.",
    };
  }

  const { latitude, longitude, radiusMeters } = boundary;

  if (!isValidCoordinate(latitude, longitude)) {
    return {
      valid: false,
      reason: "Invalid geographic coordinates.",
    };
  }

  if (!isFiniteNumber(radiusMeters)) {
    return {
      valid: false,
      reason: "radiusMeters must be a finite number.",
    };
  }

  if (
    radiusMeters < 1 ||
    radiusMeters > POLICY_CONFIG.maximumRadiusMeters
  ) {
    return {
      valid: false,
      reason: `Geographic radius must be between 1 and ${POLICY_CONFIG.maximumRadiusMeters} meters.`,
    };
  }

  return {
    valid: true,
  };
}

/* =========================================================
   INCIDENT VALIDATION
   ========================================================= */

function validateIncident(incident) {
  if (!incident || typeof incident !== "object") {
    return {
      valid: false,
      reason: "Incident information is required.",
    };
  }

  if (!isNonEmptyString(incident.incidentId)) {
    return {
      valid: false,
      reason: "incidentId is required.",
    };
  }

  if (incident.status !== "ACTIVE") {
    return {
      valid: false,
      reason: "Sensor authorization requires an ACTIVE incident.",
    };
  }

  return {
    valid: true,
  };
}

/* =========================================================
   AUTHORIZATION VALIDATION
   ========================================================= */

function validateSensorRequest(request, incident) {
  const errors = [];

  if (!request || typeof request !== "object") {
    return {
      valid: false,
      errors: ["Sensor request is required."],
    };
  }

  /* Incident */

  if (request.incidentId !== incident?.incidentId) {
    errors.push("Sensor request does not match the active incident.");
  }

  /* Sensor */

  if (!isKnownSensor(request.sensorType)) {
    errors.push("Unknown or unsupported sensor type.");
  }

  /* Purpose */

  if (!isKnownPurpose(request.purpose)) {
    errors.push("Invalid or unsupported sensor purpose.");
  }

  /* Requester */

  if (!isNonEmptyString(request.requestedBy)) {
    errors.push("requestedBy is required.");
  }

  /* Approver */

  if (!isNonEmptyString(request.approvedBy)) {
    errors.push("approvedBy is required.");
  }

  /* Geography */

  const geographicValidation = validateGeographicBoundary(
    request.geographicBoundary
  );

  if (!geographicValidation.valid) {
    errors.push(geographicValidation.reason);
  }

  /* Dates */

  const startsAt = parseDate(request.startsAt);
  const expiresAt = parseDate(request.expiresAt);
  const retentionUntil = parseDate(request.dataRetentionUntil);

  if (!startsAt) {
    errors.push("startsAt is invalid.");
  }

  if (!expiresAt) {
    errors.push("expiresAt is invalid.");
  }

  if (!retentionUntil) {
    errors.push("dataRetentionUntil is invalid.");
  }

  if (startsAt && expiresAt) {
    const durationMs = expiresAt.getTime() - startsAt.getTime();

    if (durationMs <= 0) {
      errors.push("expiresAt must be later than startsAt.");
    } else {
      const durationMinutes = durationMs / 60000;

      const capability = SENSOR_CAPABILITIES[request.sensorType];

      if (
        capability &&
        durationMinutes > capability.maxDurationMinutes
      ) {
        errors.push(
          `Requested duration exceeds the ${capability.maxDurationMinutes}-minute limit for this sensor.`
        );
      }

      if (
        durationMinutes < POLICY_CONFIG.minimumDurationMinutes
      ) {
        errors.push(
          `Requested duration must be at least ${POLICY_CONFIG.minimumDurationMinutes} minute.`
        );
      }
    }
  }

  if (startsAt) {
    const now = Date.now();
    const maximumAllowedStart =
      now + POLICY_CONFIG.maximumFutureStartMinutes * 60000;

    if (startsAt.getTime() > maximumAllowedStart) {
      errors.push(
        "Sensor activation cannot be scheduled far into the future."
      );
    }
  }

  if (retentionUntil && startsAt) {
    const retentionMs =
      retentionUntil.getTime() - startsAt.getTime();

    if (retentionMs < 0) {
      errors.push(
        "Data retention cannot end before sensor authorization begins."
      );
    }

    if (
      retentionMs >
      POLICY_CONFIG.maximumRetentionHours * 60 * 60 * 1000
    ) {
      errors.push(
        `Data retention cannot exceed ${POLICY_CONFIG.maximumRetentionHours} hours.`
      );
    }
  }

  /* Outputs */

  if (
    !Array.isArray(request.allowedOutputs) ||
    request.allowedOutputs.length === 0
  ) {
    errors.push("At least one allowed output is required.");
  } else {
    for (const output of request.allowedOutputs) {
      if (!isKnownOutput(output)) {
        errors.push(`Unsupported output: ${String(output)}`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/* =========================================================
   CREATE AUTHORIZATION
   ========================================================= */

function createSensorAuthorization(request, incident) {
  /*
   * FAIL CLOSED:
   * Never create an authorization unless every policy
   * requirement passes.
   */

  const incidentValidation = validateIncident(incident);

  if (!incidentValidation.valid) {
    return {
      authorized: false,
      errors: [incidentValidation.reason],
    };
  }

  const validation = validateSensorRequest(request, incident);

  if (!validation.valid) {
    return {
      authorized: false,
      errors: validation.errors,
    };
  }

  const capability = SENSOR_CAPABILITIES[request.sensorType];

  const authorization = {
    authorizationId: generateAuthorizationId(),

    incidentId: request.incidentId,

    sensorType: request.sensorType,

    sensorCategory: capability.category,

    purpose: request.purpose,

    geographicBoundary: {
      latitude: request.geographicBoundary.latitude,
      longitude: request.geographicBoundary.longitude,
      radiusMeters: request.geographicBoundary.radiusMeters,
    },

    requestedBy: request.requestedBy,

    approvedBy: request.approvedBy,

    startsAt: new Date(request.startsAt).toISOString(),

    expiresAt: new Date(request.expiresAt).toISOString(),

    dataRetentionUntil: new Date(
      request.dataRetentionUntil
    ).toISOString(),

    allowedOutputs: [...request.allowedOutputs],

    createdAt: new Date().toISOString(),

    status: "AUTHORIZED",

    emergencyOnly: capability.emergencyOnly,

    auditRequired: true,
  };

  return {
    authorized: true,
    authorization,
  };
}

/* =========================================================
   RUNTIME AUTHORIZATION CHECK
   ========================================================= */

function isAuthorizationActive(authorization, now = new Date()) {
  if (!authorization || typeof authorization !== "object") {
    return false;
  }

  if (authorization.status !== "AUTHORIZED") {
    return false;
  }

  const currentTime = parseDate(now);
  const startsAt = parseDate(authorization.startsAt);
  const expiresAt = parseDate(authorization.expiresAt);

  if (!currentTime || !startsAt || !expiresAt) {
    return false;
  }

  return (
    currentTime.getTime() >= startsAt.getTime() &&
    currentTime.getTime() < expiresAt.getTime()
  );
}

/* =========================================================
   GEOGRAPHIC CHECK
   ========================================================= */

function distanceBetweenCoordinates(
  lat1,
  lon1,
  lat2,
  lon2
) {
  const earthRadiusMeters = 6371000;

  const toRadians = (degrees) =>
    (degrees * Math.PI) / 180;

  const dLat = toRadians(lat2 - lat1);
  const dLon = toRadians(lon2 - lon1);

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRadians(lat1)) *
      Math.cos(toRadians(lat2)) *
      Math.sin(dLon / 2) ** 2;

  const c =
    2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return earthRadiusMeters * c;
}

function isCoordinateWithinAuthorization(
  authorization,
  latitude,
  longitude
) {
  if (!authorization) {
    return false;
  }

  if (!isValidCoordinate(latitude, longitude)) {
    return false;
  }

  const boundary = authorization.geographicBoundary;

  if (!boundary) {
    return false;
  }

  const distance = distanceBetweenCoordinates(
    boundary.latitude,
    boundary.longitude,
    latitude,
    longitude
  );

  return distance <= boundary.radiusMeters;
}

/* =========================================================
   OUTPUT CHECK
   ========================================================= */

function isOutputAllowed(authorization, output) {
  if (!authorization) {
    return false;
  }

  if (!isKnownOutput(output)) {
    return false;
  }

  return authorization.allowedOutputs.includes(output);
}

/* =========================================================
   REVOKE AUTHORIZATION
   ========================================================= */

function revokeSensorAuthorization(
  authorization,
  reason = "MANUAL_REVOCATION"
) {
  if (!authorization) {
    return {
      success: false,
      error: "Authorization is required.",
    };
  }

  authorization.status = "REVOKED";
  authorization.revokedAt = new Date().toISOString();
  authorization.revocationReason = safeReason(reason);

  return {
    success: true,
    authorization,
  };
}

/* =========================================================
   EXPIRATION
   ========================================================= */

function expireSensorAuthorization(
  authorization,
  now = new Date()
) {
  if (!authorization) {
    return {
      success: false,
      error: "Authorization is required.",
    };
  }

  const nowDate = new Date(now);
  const startsAt = new Date(authorization.startsAt);
  const expiresAt = new Date(authorization.expiresAt);

  if (
    Number.isNaN(nowDate.getTime()) ||
    Number.isNaN(startsAt.getTime()) ||
    Number.isNaN(expiresAt.getTime())
  ) {
    return {
      success: false,
      error: "Authorization timing information is invalid.",
    };
  }

  /*
   * A future authorization is NOT expired.
   * It simply has not started yet.
   */
  if (nowDate < startsAt) {
    return {
      success: false,
      error: "Authorization has not started yet.",
    };
  }

  /*
   * Only mark the authorization EXPIRED once its
   * actual expiration time has been reached.
   */
  if (nowDate >= expiresAt) {
    authorization.status = "EXPIRED";
    authorization.expiredAt = nowDate.toISOString();

    return {
      success: true,
      authorization,
    };
  }

  return {
    success: false,
    error: "Authorization has not reached its expiration time.",
  };
}

/* =========================================================
   SAFE AUDIT EVENT
   ========================================================= */

function buildAuditEvent(
  action,
  authorization,
  success,
  reason = null
) {
  return {
    eventId: crypto.randomUUID(),

    event: action,

    authorizationId:
      authorization?.authorizationId || null,

    incidentId:
      authorization?.incidentId || null,

    sensorType:
      authorization?.sensorType || null,

    requestedBy:
      authorization?.requestedBy || null,

    approvedBy:
      authorization?.approvedBy || null,

    success: Boolean(success),

    reason: reason ? safeReason(reason) : null,

    createdAt: new Date().toISOString(),
  };
}

function safeReason(value) {
  if (!isNonEmptyString(value)) {
    return null;
  }

  return value.trim().slice(0, 500);
}

/* =========================================================
   POLICY SUMMARY
   ========================================================= */

function getPolicySummary() {
  return {
    failClosed: true,

    activeIncidentRequired: true,

    geographicBoundaryRequired: true,

    explicitPurposeRequired: true,

    approvalRequired: true,

    automaticExpiration: true,

    auditRequired: true,

    maximumRetentionHours:
      POLICY_CONFIG.maximumRetentionHours,

    maximumRadiusMeters:
      POLICY_CONFIG.maximumRadiusMeters,

    sensors: Object.keys(SENSOR_CAPABILITIES),

    purposes: Object.values(PURPOSES),

    outputs: Object.values(ALLOWED_OUTPUTS),
  };
}

/* =========================================================
   EXPORTS
   ========================================================= */

module.exports = {
  SENSOR_TYPES,
  SENSOR_CAPABILITIES,
  PURPOSES,
  ALLOWED_OUTPUTS,
  POLICY_CONFIG,

  validateIncident,
  validateGeographicBoundary,
  validateSensorRequest,

  createSensorAuthorization,

  isAuthorizationActive,
  isCoordinateWithinAuthorization,
  isOutputAllowed,

  revokeSensorAuthorization,
  expireSensorAuthorization,

  buildAuditEvent,

  getPolicySummary,
};
