const express = require('express');
const { fn, col, literal } = require('sequelize');
const { requireAuth } = require('../middleware/auth');
const { Log, Alert, Incident, Asset, ThreatIntel } = require('../models');

const router = express.Router();

const OPEN_STATUSES = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING'];

router.get('/', requireAuth, async (req, res) => {
  if (req.session.user.mustChangePassword) {
    return res.redirect('/change-password');
  }

  try {
    const [totalEvents, criticalAlerts, highAlerts, openIncidents, activeAssets, maliciousIps] = await Promise.all([
      Log.count(),
      Alert.count({ where: { severity: 'CRITICAL', status: OPEN_STATUSES } }),
      Alert.count({ where: { severity: 'HIGH', status: OPEN_STATUSES } }),
      Incident.count({ where: { status: ['OPEN', 'INVESTIGATING'] } }),
      Asset.count({ where: { status: 'ACTIVE' } }),
      ThreatIntel.count({ where: { reputation: 'MALICIOUS' }, distinct: true, col: 'indicator' }),
    ]);

    // ---- Chart data ----
    // Events over the last 24 hours, bucketed by hour
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentLogs = await Log.findAll({
      attributes: ['timestamp', 'source', 'severity'],
      where: { timestamp: { [require('sequelize').Op.gte]: since } },
      raw: true,
    });

    const hourBuckets = Array(24).fill(0);
    const nowHour = new Date().getHours();
    recentLogs.forEach((l) => {
      const hoursAgo = Math.floor((Date.now() - new Date(l.timestamp).getTime()) / 3600000);
      if (hoursAgo >= 0 && hoursAgo < 24) hourBuckets[23 - hoursAgo] += 1;
    });
    const hourLabels = Array.from({ length: 24 }, (_, i) => `${(nowHour - 23 + i + 24) % 24}:00`);

    const severityCounts = await Alert.findAll({
      attributes: ['severity', [fn('COUNT', col('severity')), 'count']],
      group: ['severity'],
      raw: true,
    });

    const sourceCounts = await Log.findAll({
      attributes: ['source', [fn('COUNT', col('source')), 'count']],
      group: ['source'],
      raw: true,
    });

    const topIps = await Alert.findAll({
      attributes: ['source_ip', [fn('COUNT', col('source_ip')), 'count']],
      where: literal('source_ip IS NOT NULL'),
      group: ['source_ip'],
      order: [[literal('count'), 'DESC']],
      limit: 5,
      raw: true,
    });

    const topRules = await Alert.findAll({
      attributes: ['rule_name', [fn('COUNT', col('rule_name')), 'count']],
      group: ['rule_name'],
      order: [[literal('count'), 'DESC']],
      limit: 5,
      raw: true,
    });

    res.render('dashboard', {
      title: 'Dashboard',
      stats: { totalEvents, criticalAlerts, highAlerts, openIncidents, maliciousIps, activeAssets },
      charts: {
        timeline: { labels: hourLabels, data: hourBuckets },
        severity: severityCounts,
        sources: sourceCounts,
        topIps,
        topRules,
      },
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load dashboard.', user: req.session.user });
  }
});

module.exports = router;
