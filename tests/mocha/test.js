const assert = require('assert')
const fs = require('fs')
const path = require('path')
const cipherChain = require('../../cipher-chain')
const _ = require('lodash')

const ciphering = new cipherChain({
  secret: 'secretje',
  kdf: 'pbkdf2',
  options: {
    rounds: 10,
    hash: 'sha512'
  }
})

describe('algorithm testing', function() {
  for (let cipher in ciphering.ciphers) {
    it(cipher, async () => {
      let encrypted = await ciphering.encrypt('secret data', cipher)
      let decrypted = await ciphering.decrypt(encrypted)
      assert.equal(decrypted, 'secret data')

      encrypted = await ciphering.encrypt({ secret: true }, cipher)
      decrypted = await ciphering.decrypt(encrypted)
      assert.deepEqual(decrypted, { secret: true })
    })
  }
})

describe('chaining testing', function() {
  const chains = []

  const cipherperpart = 3
  let ciphercount = 0
  let tempchain = []
  for (let cipher in ciphering.ciphers) {
    tempchain.push(cipher)
    ciphercount++
    if (cipherperpart == ciphercount) {
      chains.push(tempchain)
      tempchain = []
      ciphercount = 0
    }
  }

  for (let chain of chains) {
    it(chain.join(' -> '), async () => {
      let encrypted = await ciphering.encrypt('secret data', chain)
      let decrypted = await ciphering.decrypt(encrypted)
      assert.equal(decrypted, 'secret data')

      encrypted = await ciphering.encrypt({ secret: true }, chain)
      decrypted = await ciphering.decrypt(encrypted)
      assert.deepEqual(decrypted, { secret: true })
    })
  }
})
