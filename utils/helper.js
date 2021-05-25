const jwt = require('jsonwebtoken');
const { jwtSecretKey } = require('../config');

exports.removeFields = (obj, keys, removeBasicFields = true) => {
    var basicFields = ['createdAt', 'updatedAt', 'isDeleted', 'deletedBy', 'deletedAt', 'password', '__v', 'createdBy', 'updatedBy'];
    keys = typeof keys == 'string' ? [keys] : keys || [];
  
    if (removeBasicFields) keys = keys.concat(basicFields);
    keys.forEach((key) => delete obj[key]);
    return obj;
};

exports.deselectFields = (keys, removeBasicFields = true) => {
    let basicFields = ['-createdAt', '-updatedAt', '-isDeleted', '-deletedBy', '-deletedAt', '-password', '-__v', '-createdBy', '-updatedBy'];
    keys = typeof keys == 'string' ? [keys] : keys || [];
    if (removeBasicFields) keys = keys.concat(basicFields);
    let keyString = keys.toString().replace(/,/g, ' ');
    return keyString;
}

exports.capitalizeFirstLetter = (string) => {
    return string.charAt(0).toUpperCase() + string.slice(1);
};

exports.jsonToObject = (json) => {
    return JSON.parse(JSON.stringify(json));
};

exports.genrateJwt = (body) => {
    return jwt.sign({ user: body }, jwtSecretKey, { expiresIn: '2 days'});
};