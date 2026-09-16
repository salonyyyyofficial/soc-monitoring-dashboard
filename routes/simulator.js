const express = require('express');
const { Log, Rule, Alert, AuditLog } = require('../models');
const { requireAuth } = require('../middleware/auth');
const simulator = require('../services/simulator');
const { parseAndSaveBatch } = require('../services/logParser');
const detectionEngine = require('../services/detectionEngine');

const router = express.Router();

const DISPLAY_NAMES = {
  'brute-force': 'Brute Force',
  'port-scan': 'Port Scan',
  'suspicious-powershell': 'Suspicious PowerShell',
  'privilege-escalation': 'Privilege Escalation',
  'malware': 'Malware Detection',
  'suspicious-login': 'Suspicious Login',
  'web-attack': 'Web Attack',
};

router.get('/simulator', requireAuth, (req, res) => {
  res.render('simulator', {
    title: 'Live Monitoring / Simulator',
    eventTypes: simulator.GENERATORS,
    displayNames: DISPLAY_NAMES,
  });
});

// Triggered by the buttons on the simulator page (AJAX POST)
router.post('/simulator/generate/:type', requireAuth, async (req, res) => {
  const { type } = req.params;

  if (!simulator.GENERATORS.includes(type)) {
    return res.status(400).json({ error: 'Unknown event type' });
  }

  try {
    const io = req.app.get('io');
    const rawEvents = simulator.generate(type);
    const savedLogs = await parseAndSaveBatch(Log, rawEvents);

    // Push each new log to every connected browser immediately.
    savedLogs.forEach((log) => {
      io.emit('new_log', log.toJSON());
    });

    // Run detection on the batch - checking the last log is sufficient for
    // threshold rules (brute force, port scan) since all logs in the batch
    // are already saved by this point, so the count query sees all of them.
    // Immediate rules (PowerShell, priv-esc, malware) match on any log in
    // the batch, so we check each one individually.
    const newAlerts = [];
    for (const log of savedLogs) {
      const alerts = await detectionEngine.evaluateLog({ Log, Rule, Alert }, log);
      newAlerts.push(...alerts);
    }

    // Push each new alert live too - this is what makes an alert "pop up"
    // on the Dashboard/Alerts page without anyone refreshing.
    newAlerts.forEach((alert) => {
      io.emit('new_alert', alert.toJSON());
    });

    await AuditLog.create({
      user_id: req.session.user.id,
      action: 'SIMULATOR_EVENT_GENERATED',
      target: type,
      ip: req.ip,
    }).catch(() => {});

    let message = `Generated ${savedLogs.length} event(s) for "${DISPLAY_NAMES[type] || type}"`;
    if (newAlerts.length > 0) {
      message += ` — ${newAlerts.length} alert(s) created!`;
    }

    res.json({
      success: true,
      type,
      count: savedLogs.length,
      alertsCreated: newAlerts.length,
      message,
    });
  } catch (err) {
    console.error('Simulator generation error:', err);
    res.status(500).json({ error: 'Failed to generate events' });
  }
});

// Clears all simulated log data (useful during demos)
router.post('/simulator/clear', requireAuth, async (req, res) => {
  try {
    const io = req.app.get('io');
    await Log.destroy({ where: {}, truncate: true });
    await Alert.destroy({ where: {}, truncate: true });
    await AuditLog.create({
      user_id: req.session.user.id,
      action: 'SIMULATOR_DATA_CLEARED',
      target: 'logs_and_alerts',
      ip: req.ip,
    }).catch(() => {});
    io.emit('data_cleared');
    res.json({ success: true, message: 'All simulated log and alert data cleared.' });
  } catch (err) {
    console.error('Simulator clear error:', err);
    res.status(500).json({ error: 'Failed to clear data' });
  }
});

module.exports = router;
