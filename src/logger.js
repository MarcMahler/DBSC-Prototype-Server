const pc = require("picocolors");

function formatValue(val) {
    if (typeof val === 'string') {
        try {
            // Check if it's a JSON string and pretty print it
            if ((val.startsWith('{') && val.endsWith('}')) || (val.startsWith('[') && val.endsWith(']'))) {
                const parsed = JSON.parse(val);
                return "\n" + JSON.stringify(parsed, null, 2);
            }
        } catch (e) {
            // Not JSON or parse error, return as is
        }
        return val;
    }
    if (typeof val === 'object' && val !== null) {
        return "\n" + JSON.stringify(val, null, 2);
    }
    return val;
}

function formatLog(level, module, message, data) {
    const timestamp = new Date().toISOString();
    const tsStr = pc.gray(timestamp);
    const modStr = pc.magenta(module.toUpperCase().padEnd(7));
    
    let levelStr = level.toUpperCase().padEnd(5);
    let msgStr = formatValue(message);
    if (data !== undefined) {
        msgStr += " " + formatValue(data);
    }

    switch (level.toUpperCase()) {
        case 'INFO':
            levelStr = pc.blue(levelStr);
            break;
        case 'WARN':
            levelStr = pc.yellow(levelStr);
            msgStr = pc.yellow(msgStr);
            break;
        case 'ERROR':
            levelStr = pc.red(levelStr);
            msgStr = pc.red(msgStr);
            break;
        case 'DEBUG':
            levelStr = pc.gray(levelStr);
            msgStr = pc.gray(msgStr);
            break;
    }

    return `[${tsStr}] ${levelStr} [${modStr}] ${msgStr}`;
}

const logger = {
    info: (module, message, data) => {
        console.log(formatLog('INFO', module, message, data));
    },
    error: (module, message, data) => {
        console.error(formatLog('ERROR', module, message, data));
    },
    warn: (module, message, data) => {
        console.warn(formatLog('WARN', module, message, data));
    },
    debug: (module, message, data) => {
        console.debug(formatLog('DEBUG', module, message, data));
    }
};

module.exports = logger;
