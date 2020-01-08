const assert = require('assert')
const fs = require('fs')
const path = require('path')
const cipherChain = require('../../cipher-chain')
const _ = require('lodash')

const ciphering = new cipherChain({
  secret: 'default settings'
})

describe(`kdf functions (${ciphering.secret})`, function() {
  const cipheringPbkdf2Child = new cipherChain({
    secret: 'default settings',
    kdf: 'pbkdf2'
  })
  const cipheringArgonChild = new cipherChain({
    secret: 'default settings',
    kdf: 'argon2'
  })
  it(`pbkdf2`, async () => {
    let hash = await cipheringPbkdf2Child.hasher('secret', cipheringPbkdf2Child.generateSalt(32), 16)
    assert.equal(32, hash.length)
  })
  it(`argon2`, async () => {
    let hash = await cipheringArgonChild.hasher('secret', cipheringArgonChild.generateSalt(32), 16)
    assert.equal(32, hash.length)
  })
})

describe(`random bytes (${ciphering.secret})`, function() {
  it(`generateSalt`, async () => {
    let salt = ciphering.generateSalt(16)
    assert.equal(32, salt.length)
  })
})

describe(`algorithm integrity (${ciphering.secret})`, function() {
  for (let ciphername in ciphering.ciphers) {
    it(`${ciphername}`, async () => {
      let encrypted = await ciphering.encrypt('secret data', ciphername)
      let decrypted = await ciphering.decrypt(encrypted)
      assert.equal(decrypted, 'secret data')

      encrypted = await ciphering.encrypt({ secret: true }, ciphername)
      decrypted = await ciphering.decrypt(encrypted)
      assert.deepEqual(decrypted, { secret: true })
    })
  }
})

describe(`encryption chain testing (${ciphering.secret})`, function() {
  const chains = []

  const cipherperpart = 3
  let ciphercount = 0
  let tempchain = []
  for (let ciphername in ciphering.ciphers) {
    tempchain.push(ciphername)
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
