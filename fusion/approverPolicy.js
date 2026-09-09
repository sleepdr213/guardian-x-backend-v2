"use strict";

/*
 * Guardian X — Approver Policy
 *
 * Purpose:
 *   Provides a fail-closed authorization layer for deciding whether
 *   an approver is permitted to approve a Guardian X sensor request.
 *
 * Security principles:
 *   - Explicit approver identity required
 *   - Explicit role required
 *   - Approver must be active
 *   - Approval scope must match the requested sensor
 *   - Emergency incident required
 *   - No hardware activation
 *   - No implicit administrator bypass
 *   - No unrestricted surveillance authorization
 *
 * IMPORTANT:
 *   This module does NOT activate sensors, drones, cameras,
 *   WAMI systems, or other hardware.
 *
 *   It only evaluates approval authority.
 */

const crypto = require("crypto");

/* ============================================================
   APPROVER ROLES
   ============================================================ */

const APPROVER_ROLES = Object.freeze({
  EMERGENCY_OPERATOR: "EMERGENCY_OPERATOR",
  SEARCH_AND_RESCUE_OPERATOR: "SEARCH_AND_RESCUE_OPERATOR",
  DRONE_OPERATOR: "DRONE_OPERATOR",
  INCIDENT_SUPERVISOR: "INCIDENT_SUPERVISOR",
});

/* ============================================================
   APPROVER STATUS
   ============================================================ */

const APPROVER_STATUS = Object.freeze({
  ACTIVE: "ACTIVE",
  SUSPENDED: "SUSPENDED",
  REVOKED: "REVOKED",
});

/* ============================================================
   SENSOR TYPES

   Kept explicit here so this policy remains fail-closed.
   ============================================================ */

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

/* ============================================================
   ROLE → SENSOR APPROVAL MATRIX
   ============================================================ */

const ROLE_SENSOR_PERMISSIONS = Object.freeze({
  [APPROVER_ROLES.EMERGENCY_OPERATOR]: Object.freeze([
    SENSOR_TYPES.DRONE_RGB,
    SENSOR_TYPES.DRONE_THERMAL,
    SENSOR_TYPES.DRONE_NIGHT_VISION,
    SENSOR_TYPES.DRONE_TELEMETRY,
    SENSOR_TYPES.WEATHER,
    SENSOR_TYPES.TERRAIN,
  ]),

  [APPROVER_ROLES.SEARCH_AND_RESCUE_OPERATOR]: Object.freeze([
    SENSOR_TYPES.DRONE_RGB,
    SENSOR_TYPES.DRONE_THERMAL,
    SENSOR_TYPES.DRONE_NIGHT_VISION,
    SENSOR_TYPES.DRONE_TELEMETRY,
    SENSOR_TYPES.SENTINEL_1,
    SENSOR_TYPES.WEATHER,
    SENSOR_TYPES.TERRAIN,
  ]),

  [APPROVER_ROLES.DRONE_OPERATOR]: Object.freeze([
    SENSOR_TYPES.DRONE_RGB,
    SENSOR_TYPES.DRONE_THERMAL,
    SENSOR_TYPES.DRONE_NIGHT_VISION,
    SENSOR_TYPES.DRONE_TELEMETRY,
  ]),

  [APPROVER_ROLES.INCIDENT_SUPERVISOR]: Object.freeze([
    SENSOR_TYPES.DRONE_RGB,
    SENSOR_TYPES.DRONE_THERMAL,
    SENSOR_TYPES.DRONE_NIGHT_VISION,
    SENSOR_TYPES.DRONE_WAMI,
    SENSOR_TYPES.DRONE_TELEMETRY,
    SENSOR_TYPES.SENTINEL_1,
    SENSOR_TYPES.WEATHER,
    SENSOR_TYPES.TERRAIN,
  ]),
});

/* ============================================================
   HELPERS
   ============================================================ */

function safeString(value, maxLength = 200) {
  if (typeof value !== "string") {
    return "";
  }

  return value.trim().slice(0, maxLength);
}

function isKnownRole(role) {
  return Object.values(APPROVER_ROLES).includes(role);
}

function isKnownStatus(status) {
  return Object.values(APPROVER_STATUS).includes(status);
}

function isKnownSensor(sensorType) {
  return Object.values(SENSOR_TYPES).includes(sensorType);
}

/* ============================================================
   APPROVER VALIDATION
   ============================================================ */

function validateApprover(approver) {
  const errors = [];

  if (!approver || typeof approver !== "object") {
    return {
      success: false,
      errors: ["Approver is required."],
    };
  }

  const approverId = safeString(approver.approverId);

  if (!approverId) {
    errors.push("Approver ID is required.");
  }

  if (!isKnownRole(approver.role)) {
    errors.push("Approver role is invalid.");
  }

  if (!isKnownStatus(approver.status)) {
    errors.push("Approver status is invalid.");
  }

  if (
    isKnownStatus(approver.status) &&
    approver.status !== APPROVER_STATUS.ACTIVE
  ) {
    errors.push("Approver is not active.");
  }

  return {
    success: errors.length === 0,
    errors,
  };
}

/* ============================================================
   INCIDENT VALIDATION
   ============================================================ */

function validateIncident(incident) {
  const errors = [];

  if (!incident || typeof incident !== "object") {
    return {
      success: false,
      errors: ["Incident is required."],
    };
  }

  const incidentId = safeString(incident.incidentId);

  if (!incidentId) {
    errors.push("Incident ID is required.");
  }

  if (incident.status !== "ACTIVE") {
    errors.push("Incident must be ACTIVE.");
  }

  return {
    success: errors.length === 0,
    errors,
  };
}

/* ============================================================
   ROLE PERMISSION CHECK
   ============================================================ */

function canRoleApproveSensor(role, sensorType) {
  if (!isKnownRole(role)) {
    return false;
  }

  if (!isKnownSensor(sensorType)) {
    return false;
  }

  const allowedSensors = ROLE_SENSOR_PERMISSIONS[role];

  if (!Array.isArray(allowedSensors)) {
    return false;
  }

  return allowedSensors.includes(sensorType);
}

/* ============================================================
   APPROVAL REQUEST VALIDATION
   ============================================================ */

function validateApprovalRequest({
  incident,
  approver,
  sensorType,
}) {
  const errors = [];

  const incidentValidation = validateIncident(incident);

  if (!incidentValidation.success) {
    errors.push(...incidentValidation.errors);
  }

  const approverValidation = validateApprover(approver);

  if (!approverValidation.success) {
    errors.push(...approverValidation.errors);
  }

  if (!isKnownSensor(sensorType)) {
    errors.push("Sensor type is invalid.");
  }

  if (
    approverValidation.success &&
    isKnownSensor(sensorType) &&
    !canRoleApproveSensor(approver.role, sensorType)
  ) {
    errors.push(
      "Approver role is not authorized for this sensor type."
    );
  }

  return {
    success: errors.length === 0,
    errors,
  };
}

/* ============================================================
   CREATE VERIFIED APPROVAL

   This creates an approval record only.
   It does NOT activate hardware.
   ============================================================ */

function createVerifiedApproval({
  incident,
  approver,
  sensorType,
  requestedBy,
  now = new Date(),
}) {
  const validation = validateApprovalRequest({
    incident,
    approver,
    sensorType,
  });

  if (!validation.success) {
    return {
      success: false,
      errors: validation.errors,
    };
  }

  const requester = safeString(requestedBy);

  if (!requester) {
    return {
      success: false,
      errors: ["Requested-by identity is required."],
    };
  }

  const nowDate = new Date(now);

  if (Number.isNaN(nowDate.getTime())) {
    return {
      success: false,
      errors: ["Approval timestamp is invalid."],
    };
  }

  const approval = {
    approvalId: crypto.randomUUID(),

    incidentId: safeString(incident.incidentId),

    sensorType,

    requestedBy: requester,

    approvedBy: safeString(approver.approverId),

    approverRole: approver.role,

    approvedAt: nowDate.toISOString(),

    status: "APPROVED",

    hardwareActivation: false,

    auditRequired: true,
  };

  return {
    success: true,
    approval,
  };
}

/* ============================================================
   APPROVAL VERIFICATION
   ============================================================ */

function verifyApprovalForSensor({
  approval,
  incident,
  sensorType,
}) {
  const errors = [];

  if (!approval || typeof approval !== "object") {
    return {
      success: false,
      errors: ["Approval is required."],
    };
  }

  const incidentValidation = validateIncident(incident);

  if (!incidentValidation.success) {
    errors.push(...incidentValidation.errors);
  }

  if (
    safeString(approval.incidentId) !==
    safeString(incident && incident.incidentId)
  ) {
    errors.push("Approval incident does not match.");
  }

  if (!isKnownSensor(sensorType)) {
    errors.push("Sensor type is invalid.");
  }

  if (approval.sensorType !== sensorType) {
    errors.push("Approval sensor type does not match.");
  }

  if (approval.status !== "APPROVED") {
    errors.push("Approval is not active.");
  }

  if (!safeString(approval.approvedBy)) {
    errors.push("Approval does not contain an approver.");
  }

  if (!isKnownRole(approval.approverRole)) {
    errors.push("Approval contains an invalid approver role.");
  }

  if (
    isKnownRole(approval.approverRole) &&
    isKnownSensor(sensorType) &&
    !canRoleApproveSensor(
      approval.approverRole,
      sensorType
    )
  ) {
    errors.push(
      "Approval role is not permitted for this sensor."
    );
  }

  return {
    success: errors.length === 0,
    errors,
  };
}

/* ============================================================
   SAFE AUDIT EVENT
   ============================================================ */

function buildApprovalAuditEvent({
  action,
  approval = null,
  success,
  reason = null,
  now = new Date(),
}) {
  const nowDate = new Date(now);

  return {
    eventId: crypto.randomUUID(),

    event: safeString(action),

    approvalId:
      approval && approval.approvalId
        ? safeString(approval.approvalId)
        : null,

    incidentId:
      approval && approval.incidentId
        ? safeString(approval.incidentId)
        : null,

    sensorType:
      approval && approval.sensorType
        ? approval.sensorType
        : null,

    approvedBy:
      approval && approval.approvedBy
        ? safeString(approval.approvedBy)
        : null,

    success: Boolean(success),

    reason:
      reason === null
        ? null
        : safeString(String(reason), 500),

    timestamp:
      Number.isNaN(nowDate.getTime())
        ? new Date().toISOString()
        : nowDate.toISOString(),
  };
}

/* ============================================================
   POLICY STATUS
   ============================================================ */

function getApproverPolicyStatus() {
  return {
    version: "1.0.0",

    failClosed: true,

    approverIdentityRequired: true,

    approverRoleRequired: true,

    activeApproverRequired: true,

    activeIncidentRequired: true,

    roleSensorScopeEnforced: true,

    auditRequired: true,

    hardwareActivation: false,

    unrestrictedApprovalAllowed: false,

    supportedRoles: Object.values(APPROVER_ROLES),

    supportedSensors: Object.values(SENSOR_TYPES),
  };
}

/* ============================================================
   EXPORTS
   ============================================================ */

module.exports = {
  APPROVER_ROLES,
  APPROVER_STATUS,
  SENSOR_TYPES,
  ROLE_SENSOR_PERMISSIONS,

  validateApprover,
  validateIncident,

  canRoleApproveSensor,
  validateApprovalRequest,

  createVerifiedApproval,
  verifyApprovalForSensor,

  buildApprovalAuditEvent,

  getApproverPolicyStatus,
};
