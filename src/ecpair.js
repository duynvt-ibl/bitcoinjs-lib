var randomBytes = require('randombytes')
var typeforce = require('typeforce')
var types = require('./types')
var wif = require('wif')

var NETWORKS = require('./networks')
var tinysecp = require('tiny-secp256k1')

function isPrivate (x) { return tinysecp.isPrivate(x) }
function isPoint (x) { return tinysecp.isPoint(x) }

function ECPair (d, Q, options) {
  options = options || {}

  typeforce({
    d: types.maybe(isPrivate),
    Q: types.maybe(isPoint),
    options: {
      compressed: types.maybe(types.Boolean),
      network: types.maybe(types.Network)
    }
  }, {
    d: d,
    Q: Q,
    options: options
  })

  this.compressed = options.compressed === undefined ? true : options.compressed
  this.network = options.network || NETWORKS.bitcoin

  if (d) {
    if (Q) throw new TypeError('Unexpected publicKey parameter')

    this.__d = d
  } else {
    this.__Q = tinysecp.pointCompress(Q, this.compressed)
  }
}

ECPair.prototype.getNetwork = function () {
  return this.network
}

ECPair.prototype.getPrivateKeyBuffer = function () {
  return this.__d
}

ECPair.prototype.getPublicKeyBuffer = function () {
  if (!this.__Q) this.__Q = tinysecp.pointFromScalar(this.__d, this.compressed)
  return this.__Q
}

ECPair.prototype.sign = function (hash) {
  if (!this.__d) throw new Error('Missing private key')
  return tinysecp.sign(hash, this.__d)
}

ECPair.prototype.toWIF = function () {
  if (!this.__d) throw new Error('Missing private key')
  return wif.encode(this.network.wif, this.__d, this.compressed)
}

ECPair.prototype.verify = function (hash, signature) {
  return tinysecp.verify(hash, this.getPublicKeyBuffer(), signature)
}

function fromWIF (string, network) {
  var decoded = wif.decode(string)
  var version = decoded.version

  // list of networks?
  if (types.Array(network)) {
    network = network.filter(function (x) {
      return version === x.wif
    }).pop()

    if (!network) throw new Error('Unknown network version')

  // otherwise, assume a network object (or default to bitcoin)
  } else {
    network = network || NETWORKS.bitcoin

    if (version !== network.wif) throw new Error('Invalid network version')
  }

  return new ECPair(decoded.privateKey, null, {
    compressed: decoded.compressed,
    network: network
  })
}

function fromPrivateKey (buffer, options) {
  return new ECPair(buffer, null, options)
}

function fromPublicKey (buffer, options) {
  return new ECPair(null, buffer, options)
}

function makeRandom (options) {
  options = options || {}
  var rng = options.rng || randomBytes

  var d
  do {
    d = rng(32)
    typeforce(types.Buffer256bit, d)
  } while (!tinysecp.isPrivate(d))

  return new ECPair(d, null, options)
}

module.exports = {
  makeRandom,
  fromPrivateKey,
  fromPublicKey,
  fromWIF
}
