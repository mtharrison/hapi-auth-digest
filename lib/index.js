// Load modules

var Boom = require('boom');
var Hoek = require('hoek');


// Declare internals

var internals = {};


exports.register = function (plugin, options, next) {

    plugin.auth.scheme('digest', internals.implementation);
    next();
};


exports.register.attributes = {
    pkg: require('../package.json')
};


internals.implementation = function (server, options) {

    Hoek.assert(options, 'Missing digest auth strategy options');
    Hoek.assert(typeof options.validateFunc === 'function', 'options.validateFunc must be a valid function in digest scheme');

    var settings = Hoek.clone(options);

    var scheme = {
        authenticate: function (request, reply) {

            var req = request.raw.req;
            var authorization = req.headers.authorization;
            if (!authorization) {
                return reply(Boom.unauthorized(null, 'Digest'));
            }

            var parts = authorization.split(/\s+/);

            if (parts[0].toLowerCase() !== 'digest') {
                return reply(Boom.unauthorized(null, 'Digest'));
            }

            if (parts.length !== 2) {
                return reply(Boom.badRequest('Bad HTTP authentication header format', 'Digest'));
            }

            var credentialsPart = new Buffer(parts[1], 'base64').toString();
            var sep = credentialsPart.indexOf(':');
            if (sep === -1) {
                return reply(Boom.badRequest('Bad header internal syntax', 'Digest'));
            }

            var username = credentialsPart.slice(0, sep);
            var password = credentialsPart.slice(sep + 1);

            if (!username && !settings.allowEmptyUsername) {
                return reply(Boom.unauthorized('HTTP authentication header missing username', 'Digest'));
            }

            settings.validateFunc(request, username, password, function (err, isValid, credentials) {

                credentials = credentials || null;

                if (err) {
                    return reply(err, null, { credentials: credentials });
                }

                if (!isValid) {
                    return reply(Boom.unauthorized('Bad username or password', 'Digest'), null, { credentials: credentials });
                }

                if (!credentials ||
                    typeof credentials !== 'object') {

                    return reply(Boom.badImplementation('Bad credentials object received for Digest auth validation'));
                }

                // Authenticated

                return reply.continue({ credentials: credentials });
            });
        }
    };

    return scheme;
};


