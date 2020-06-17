const assert = require('nanoassert')

module.exports = Chacha20

const constant = [1634760805, 857760878, 2036477234, 1797285236]

function Chacha20 (n, k, counter) {
  assert(k.byteLength === 32)
  assert(n.byteLength === 8 || n.byteLength === 12)

  if (!counter) counter = 0
  assert(counter < Number.MAX_SAFE_INTEGER)

  this.finalized = false
  this.pos = 0
  this.state = new Uint32Array(16)

  for (let i = 0; i < 4; i++) this.state[i] = constant[i]
  for (let i = 0; i < 8; i++) this.state[4 + i] = k.readUInt32LE(4 * i)

  this.state[12] = counter & 0xffffffff

  if (n.byteLength === 8) {
    this.state[13] = (counter && 0xffffffff00000000) >> 32
    this.state[14] = n.readUInt32LE(0)
    this.state[15] = n.readUInt32LE(4)
  } else {
    this.state[13] = n.readUInt32LE(0)
    this.state[14] = n.readUInt32LE(4)
    this.state[15] = n.readUInt32LE(8)
  }

  return this
}

Chacha20.prototype.update = function (output, input) {
  assert(!this.finalized, 'cipher finalized.')
  assert(output.byteLength >= input.byteLength,
    'output cannot be shorter than input.')

  let len = input.length
  let offset = this.pos % 64
  this.pos += len

  // input position
  let j = 0

  let keyStream = chacha20Block(this.state)

  // try to finsih the current block
  while (offset > 0 && len > 0) {
    output[j] = input[j++] ^ keyStream[offset]
    offset = (offset + 1) & 0x3f
    if (!offset) this.state[12]++
    len--
  }

  // encrypt rest block at a time
  while (len > 0) {
    keyStream = chacha20Block(this.state)

    // less than a full block remaining
    if (len < 64) {
      for (let i = 0; i < len; i++) {
        output[j] = input[j++] ^ keyStream[offset++]
        offset &= 0x3f
      }

      return
    }

    for (; offset < 64;) {
      output[j] = input[j++] ^ keyStream[offset++]
    }

    this.state[12]++
    offset = 0
    len -= 64
  }
}

Chacha20.prototype.final = function () {
  this.finalized = true
}

function chacha20Block (state) {
  // working state
  const ws = new Uint32Array(16)
  for (let i = 16; i--;) ws[i] = state[i]

  for (let i = 0; i < 20; i += 2) {
    QR(ws, 0, 4, 8, 12) // column 0
    QR(ws, 1, 5, 9, 13) // column 1
    QR(ws, 2, 6, 10, 14) // column 2
    QR(ws, 3, 7, 11, 15) // column 3

    QR(ws, 0, 5, 10, 15) // diagonal 1 (main diagonal)
    QR(ws, 1, 6, 11, 12) // diagonal 2
    QR(ws, 2, 7, 8, 13) // diagonal 3
    QR(ws, 3, 4, 9, 14) // diagonal 4
  }

  for (let i = 0; i < 16; i++) {
    ws[i] += state[i]
  }

  return Buffer.from(ws.buffer, ws.byteOffset, ws.byteLength)
}

function rotl (a, b) {
  return ((a << b) | (a >>> (32 - b)))
}

function QR (obj, a, b, c, d) {
  obj[a] += obj[b]
  obj[d] ^= obj[a]
  obj[d] = rotl(obj[d], 16)

  obj[c] += obj[d]
  obj[b] ^= obj[c]
  obj[b] = rotl(obj[b], 12)

  obj[a] += obj[b]
  obj[d] ^= obj[a]
  obj[d] = rotl(obj[d], 8)

  obj[c] += obj[d]
  obj[b] ^= obj[c]
  obj[b] = rotl(obj[b], 7)
}
