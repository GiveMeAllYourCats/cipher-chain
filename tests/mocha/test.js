const assert = require('assert')
const fs = require('fs')
const path = require('path')
const cipherChain = require('../../cipher-chain')
const _ = require('lodash')

const instances = [
  new cipherChain({
    secret: 'fast pbkdf2',
    kdf: 'pbkdf2',
    options: {
      rounds: 10,
      hash: 'sha512'
    }
  }),
  new cipherChain({
    secret: 'fast argon2',
    kdf: 'argon2',
    options: {
      timeCost: 4,
      memoryCost: 8
    }
  }),
  new cipherChain({
    secret: 'argon2 default settings',
    kdf: 'argon2'
  }),
  new cipherChain({
    secret: 'pbkdf2 default settings',
    kdf: 'pbkdf2'
  }),
  new cipherChain({
    secret: 'default settings'
  })
]

for (let ciphering of instances) {
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
}

for (let ciphering of instances) {
  describe(`encryption chain testing (${ciphering.secret})`, function() {
    const chains = []

    const cipherperpart = 3
    let ciphercount = 0
    let tempchain = []
    for (let ciphername in instances[0].ciphers) {
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
}
