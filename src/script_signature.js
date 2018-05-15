let bip66 = require('bip66')
let Buffer = require('safe-buffer').Buffer

let ZERO = Buffer.alloc(1, 0)
function toDER (x) {
  if (x[0] & 0x80) return Buffer.concat([ZERO, x], x.length + 1)
  return x
}

function fromDER (x) {
  let buffer = Buffer.alloc(32, 0)
  let xstart = Math.max(0, x.length - 32)
  x.copy(buffer, 0, xstart)
  return buffer
}

// BIP62: 1 byte hashType flag (only 0x01, 0x02, 0x03, 0x81, 0x82 and 0x83 are allowed)
function decode (buffer) {
  let hashType = buffer.readUInt8(buffer.length - 1)
  let hashTypeMod = hashType & ~0x80
  if (hashTypeMod <= 0 || hashTypeMod >= 4) throw new Error('Invalid hashType ' + hashType)

  let decode = bip66.decode(buffer.slice(0, -1))

  return {
    signature: Buffer.concat([fromDER(decode.r), fromDER(decode.s)], 64),
    hashType: hashType
  }
}

function encode (signature, hashType) {
  let hashTypeMod = hashType & ~0x80
  if (hashTypeMod <= 0 || hashTypeMod >= 4) throw new Error('Invalid hashType ' + hashType)

  let hashTypeBuffer = Buffer.allocUnsafe(1)
  hashTypeBuffer.writeUInt8(hashType, 0)

  let r = toDER(signature.slice(0, 32))
  let s = toDER(signature.slice(32, 64))

  return Buffer.concat([
    bip66.encode(r, s),
    hashTypeBuffer
  ])
}

module.exports = {
  decode: decode,
  encode: encode
}
