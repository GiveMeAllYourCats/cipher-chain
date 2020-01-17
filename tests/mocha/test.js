const assert = require('assert')
const CipherChain = require('../../cipher-chain')

before(async function() {
  instance = await new CipherChain({
    chain: ['aes-256-gcm'],
    secret: 'ThiSss23ShoulddBea!!@#hardPass'
  })
  return instance
})
let instance
context('CipherChain Test Suite', async function() {
  before(async function() {
    const instance = await new CipherChain({
      chain: ['aes-256-gcm'],
      secret: 'ThiSss23ShoulddBea!!@#hardPass'
    })

    describe('KDF', async function() {
      instance.kdfs.forEach(function(kdf, index) {
        context(kdf, async function() {
          it(`should be nice`, async function() {
            return true
          })
        })
      })
    })

    describe('Symmetric Cipher Algorithm', async function() {
      instance.kdfs.forEach(function(kdf, index) {
        context(kdf, async function() {
          it(`should be nice`, async function() {
            return true
          })
        })
      })
    })
  })

  it('Stub', async function() {
    return true
  })
})
