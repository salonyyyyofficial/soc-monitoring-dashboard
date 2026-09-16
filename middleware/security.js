const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const helmetMiddleware = helmet({
  contentSecurityPolicy: false,
});

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts. Please try again later.',
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = { helmetMiddleware, loginLimiter, apiLimiter };
