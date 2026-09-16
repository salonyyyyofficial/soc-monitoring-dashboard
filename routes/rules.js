const express = require('express');
const { Rule } = require('../models');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/rules', requireAuth, async (req, res) => {
  try {
    const rules = await Rule.findAll({ order: [['id', 'ASC']] });
    res.render('rules', { title: 'Detection Rules', rules });
  } catch (err) {
    console.error('Rules page error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load rules.', user: req.session.user });
  }
});

module.exports = router;
