/**
 * detectionEngine.js
 *
 * Called right after a log is saved (see routes/simulator.js).
 * Checks the new log against each enabled rule and creates an Alert
 * when a rule matches. Threshold rules (brute force, port scan) query
 * recent logs to look for a pattern; immediate rules (PowerShell,
 * privilege escalation, malware) match on the single event itself.
 *
 * Dedup: to avoid spamming duplicate alerts every time a fresh log
 * keeps re-triggering an already-matched pattern, each threshold rule
 * checks whether an open (NEW/ACKNOWLEDGED/INVESTIGATING) alert for the
 * same rule + source IP already exists before creating another.
 */

const { Op } = require('sequelize');
const { calculateRisk } = require('./riskEngine');

const OPEN_STATUSES = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING'];

async function hasOpenAlert(Alert, ruleName, sourceIp) {
  if (!sourceIp) return false;
  const existing = await Alert.findOne({
    where: {
      rule_name: ruleName,
      source_ip: sourceIp,
      status: { [Op.in]: OPEN_STATUSES },
    },
  });
  return !!existing;
}

async function createAlert(Alert, { rule, log, repeatedEvents, relatedLogIds }) {
  const { score, explanation } = calculateRisk({
    severity: rule.severity,
    repeatedEvents,
  });

  return Alert.create({
    title: rule.title,
    description: rule.description,
    severity: rule.severity,
    risk_score: score,
    source_ip: log.source_ip,
    username: log.username,
    hostname: log.hostname,
    rule_name: rule.name,
    mitre_id: rule.mitre_id,
    status: 'NEW',
    related_log_ids: JSON.stringify(relatedLogIds || [log.id]),
    risk_explanation: explanation.join('; '),
  });
}

// ---- Threshold rules ----

async function checkBruteForce({ Log, Alert, log, rule }) {
  if (log.event_type !== 'FAILED_LOGIN' || !log.source_ip) return null;
  if (await hasOpenAlert(Alert, rule.name, log.source_ip)) return null;

  const windowStart = new Date(Date.now() - rule.windowMinutes * 60 * 1000);
  const recentLogs = await Log.findAll({
    where: {
      event_type: 'FAILED_LOGIN',
      source_ip: log.source_ip,
      timestamp: { [Op.gte]: windowStart },
    },
    order: [['timestamp', 'ASC']],
  });

  if (recentLogs.length >= rule.threshold) {
    return createAlert(Alert, {
      rule,
      log,
      repeatedEvents: true,
      relatedLogIds: recentLogs.map((l) => l.id),
    });
  }
  return null;
}

async function checkPortScan({ Log, Alert, log, rule }) {
  if (log.event_type !== 'PORT_SCAN' || !log.source_ip) return null;
  if (await hasOpenAlert(Alert, rule.name, log.source_ip)) return null;

  const windowStart = new Date(Date.now() - rule.windowSeconds * 1000);
  const recentLogs = await Log.findAll({
    where: {
      event_type: 'PORT_SCAN',
      source_ip: log.source_ip,
      timestamp: { [Op.gte]: windowStart },
    },
    order: [['timestamp', 'ASC']],
  });

  if (recentLogs.length >= rule.threshold) {
    return createAlert(Alert, {
      rule,
      log,
      repeatedEvents: true,
      relatedLogIds: recentLogs.map((l) => l.id),
    });
  }
  return null;
}

// ---- Immediate rules ----

async function checkSuspiciousPowerShell({ Alert, log, rule }) {
  if (log.event_type !== 'SUSPICIOUS_POWERSHELL') return null;
  const haystack = `${log.message} ${log.raw_log}`;
  const matched = (rule.keywords || []).some((kw) => haystack.includes(kw));
  if (!matched) return null;
  return createAlert(Alert, { rule, log, repeatedEvents: false });
}

async function checkPrivilegeEscalation({ Alert, log, rule }) {
  if (log.event_type !== 'PRIVILEGE_ESCALATION') return null;
  return createAlert(Alert, { rule, log, repeatedEvents: false });
}

async function checkMalware({ Alert, log, rule }) {
  if (log.event_type !== 'MALWARE_DETECTED') return null;
  return createAlert(Alert, { rule, log, repeatedEvents: false });
}

const RULE_CHECKS = {
  'brute-force': checkBruteForce,
  'port-scan': checkPortScan,
  'suspicious-powershell': checkSuspiciousPowerShell,
  'privilege-escalation': checkPrivilegeEscalation,
  'malware': checkMalware,
};

/**
 * Evaluates a single saved Log instance against all enabled rules.
 * @param {object} models - { Log, Rule, Alert } Sequelize models
 * @param {object} log - the saved Log instance
 * @returns {Promise<Array>} any Alerts created
 */
async function evaluateLog(models, log) {
  const { Log, Rule, Alert } = models;
  const rules = await Rule.findAll({ where: { enabled: true } });
  const createdAlerts = [];

  for (const rule of rules) {
    const check = RULE_CHECKS[rule.name];
    if (!check) continue;
    try {
      const alert = await check({ Log, Alert, log, rule });
      if (alert) createdAlerts.push(alert);
    } catch (err) {
      console.error(`Detection engine error running rule "${rule.name}":`, err);
    }
  }

  return createdAlerts;
}

module.exports = { evaluateLog };
