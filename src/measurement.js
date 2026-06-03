// measurement.js
const fs = require("fs");
const crypto = require("crypto");
const logger = require("./logger");

const MODULE = "measure";
const MEASUREMENTS_FILE =
    process.env.MEASUREMENTS_FILE || "src/measurements.ndjson";

const activeMeasurements = new Map();

function isEnabled() {
  return logger.MEASUREMENTS_ENABLED === true;
}

function nowNs() {
  return process.hrtime.bigint();
}

function nsToMs(ns) {
  return Number(ns) / 1_000_000;
}

function writeMeasurement(row) {
  if (!isEnabled()) {
    return;
  }

  const enrichedRow = {
    timestamp: new Date().toISOString(),
    ...row
  };

  fs.appendFileSync(
      MEASUREMENTS_FILE,
      JSON.stringify(enrichedRow) + "\n"
  );
}

function newRequestId() {
  return crypto.randomUUID();
}

function startMeasurement(name, metadata = {}) {
  if (!isEnabled()) {
    return null;
  }

  const measurementId = crypto.randomUUID();

  activeMeasurements.set(measurementId, {
    measurementId,
    name,
    metadata,
    startNs: nowNs(),
    startTimestamp: new Date().toISOString()
  });

  logger.debug(MODULE, `Started measurement: ${name}`, {
    measurement_id: measurementId,
    ...metadata
  });

  return measurementId;
}

function endMeasurement(measurementId, metadata = {}) {
  if (!isEnabled() || measurementId === null) {
    return null;
  }

  const measurement = activeMeasurements.get(measurementId);

  if (!measurement) {
    logger.warn(MODULE, "Tried to end unknown measurement", {
      measurement_id: measurementId
    });
    return null;
  }

  const endNs = nowNs();
  const durationMs = nsToMs(endNs - measurement.startNs);

  const row = {
    type: "duration",
    measurement_id: measurement.measurementId,
    name: measurement.name,
    duration_ms: durationMs,
    start_timestamp: measurement.startTimestamp,
    end_timestamp: new Date().toISOString(),
    ...measurement.metadata,
    ...metadata
  };

  activeMeasurements.delete(measurementId);
  writeMeasurement(row);

  logger.debug(MODULE, `Ended measurement: ${measurement.name}`, {
    measurement_id: measurement.measurementId,
    duration_ms: durationMs,
    result: metadata.result
  });

  return row;
}

function measurePoint(name, metadata = {}) {
  if (!isEnabled()) {
    logger.warn(MODULE, "Measurement point skipped because disabled", {
      name,
      env: process.env.MEASUREMENTS_ENABLED,
      logger_flag: logger.MEASUREMENTS_ENABLED
    });
    return;
  }

  writeMeasurement({
    type: "point",
    name,
    ...metadata
  });

  logger.debug(MODULE, `Measurement point: ${name}`, metadata);
}

async function measureAsync(name, metadata, fn) {
  const measurementId = startMeasurement(name, metadata);

  try {
    const result = await fn();

    endMeasurement(measurementId, {
      result: "success"
    });

    return result;
  } catch (err) {
    endMeasurement(measurementId, {
      result: "error",
      error: err.message
    });

    throw err;
  }
}

function measureSync(name, metadata, fn) {
  const measurementId = startMeasurement(name, metadata);

  try {
    const result = fn();

    endMeasurement(measurementId, {
      result: "success"
    });

    return result;
  } catch (err) {
    endMeasurement(measurementId, {
      result: "error",
      error: err.message
    });

    throw err;
  }
}

module.exports = {
  newRequestId,
  startMeasurement,
  endMeasurement,
  measurePoint,
  measureAsync,
  measureSync
};