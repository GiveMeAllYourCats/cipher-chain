const assert = require('assert')
const fs = require('fs')
const path = require('path')
const cipherChain = require('../../cipher-chain')
const _ = require('lodash')

const ciphering = new cipherChain('secretje')

describe('algorithm testing', function() {
  for (let cipher in ciphering.ciphers) {
    it(cipher, async () => {
      let encrypted = await ciphering.encrypt('secret data', cipher)
      let decrypted = await ciphering.decrypt(encrypted)
      assert.equal(decrypted, 'secret data')
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
    })
  }
})
