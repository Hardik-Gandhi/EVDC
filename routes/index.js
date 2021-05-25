var express = require('express');
var router = express.Router();

/**
 * ROUTES
 */
router.use('/', require('./auth'));

module.exports = router;
