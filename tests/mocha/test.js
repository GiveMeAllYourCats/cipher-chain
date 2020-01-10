const assert = require('assert')
const _ = require('lodash')
const crypto = require('crypto')
const cipherChain = require('../../cipher-chain')

const bannedCiphers = [
  'aes-128-xts',
  'aes-256-xts',
  'aes-wrap',
  'aes128-wrap',
  'aes192-wrap',
  'aes256-wrap',
  'des3-wrap',
  'id-aes128-wrap',
  'id-aes192-wrap',
  'id-aes256-wrap',
  'id-smime-alg-CMS3DESwrap'
]

const cipheringPbkdf2 = new cipherChain({
  secret: 'default settings',
  kdf: 'pbkdf2',
  saltLength: 4,
  options: {
    rounds: 1
  }
})
const cipheringArgon = new cipherChain({
  secret: 'default settings',
  kdf: 'argon2',
  saltLength: 4,
  options: {
    timeCost: 1,
    memoryCost: 8
  }
})

const identicalSalt = cipheringArgon.generateSalt(6)

const cipheringPbkdf2SaltTest = new cipherChain({
  secret: 'secret',
  kdf: 'pbkdf2',
  saltLength: 4,
  salt: identicalSalt,
  options: {
    rounds: 1
  }
})

const cipheringArgonSaltTest = new cipherChain({
  secret: 'secret',
  kdf: 'argon2',
  saltLength: 4,
  salt: identicalSalt,
  options: {
    timeCost: 1,
    memoryCost: 8
  }
})

describe(`kdf nodejs internal functions`, function() {
  for (let hash of crypto.getHashes()) {
    it(`${hash} proper output`, async () => {
      const instance = new cipherChain({
        saltLength: 4,
        secret: 'secret',
        kdf: hash
      })

      await instance.ready()

      let hash1 = await instance.hasher('samesecret', 'samesalt', 16)
      const hash2 = await instance.hasher('samesecret', 'samesalt', 16)
      assert.equal(hash1, hash2)

      const hash3 = await instance.hasher('samesecret', 'samesalt1', 16)
      const hash4 = await instance.hasher('samesecret', 'samesalt2', 16)
      assert.notEqual(hash3, hash4)

      const hash5 = await instance.hasher('samesecret1', 'samesalt', 16)
      const hash6 = await instance.hasher('samesecret2', 'samesalt', 16)
      assert.notEqual(hash5, hash6)

      hash1 = await instance.hasher('secret', instance.generateSalt(4), 16)
      assert.equal(16 * 2, hash1.length)

      hash1 = await instance.hasher('secret', instance.generateSalt(4), 8)
      assert.equal(8 * 2, hash1.length)

      const encrypted = await instance.encrypt('secret data', 'aes-256-ctr')
      const decrypted = await instance.decrypt(encrypted)
      assert.equal(decrypted, 'secret data')
    })
  }
})

describe(`kdf custom functions`, function() {
  it(`pbkdf2 proper output`, async () => {
    await cipheringPbkdf2.ready()
    let hash = await cipheringPbkdf2.hasher('samesecret', 'samesalt', 16)
    const hash2 = await cipheringPbkdf2.hasher('samesecret', 'samesalt', 16)
    assert.equal(hash, hash2)

    const hash3 = await cipheringPbkdf2.hasher('samesecret', 'samesalt1', 16)
    const hash4 = await cipheringPbkdf2.hasher('samesecret', 'samesalt2', 16)
    assert.notEqual(hash3, hash4)

    const hash5 = await cipheringPbkdf2.hasher('samesecret1', 'samesalt', 16)
    const hash6 = await cipheringPbkdf2.hasher('samesecret2', 'samesalt', 16)
    assert.notEqual(hash5, hash6)

    hash = await cipheringPbkdf2.hasher('secret', cipheringArgon.generateSalt(4), 16)
    assert.equal(16 * 2, hash.length)

    hash = await cipheringPbkdf2.hasher('secret', cipheringArgon.generateSalt(4), 8)
    assert.equal(8 * 2, hash.length)

    const encrypted = await cipheringPbkdf2.encrypt('secret data', 'aes-256-ctr')
    const decrypted = await cipheringPbkdf2.decrypt(encrypted)
    assert.equal(decrypted, 'secret data')
  })
  it(`argon2 proper output`, async () => {
    await cipheringArgon.ready()
    let hash = await cipheringArgon.hasher('samesecret', 'samesalt', 16)
    const hash2 = await cipheringArgon.hasher('samesecret', 'samesalt', 16)
    assert.equal(hash, hash2)

    const hash3 = await cipheringArgon.hasher('samesecret', 'samesalt1', 16)
    const hash4 = await cipheringArgon.hasher('samesecret', 'samesalt2', 16)
    assert.notEqual(hash3, hash4)

    const hash5 = await cipheringArgon.hasher('samesecret1', 'samesalt', 16)
    const hash6 = await cipheringArgon.hasher('samesecret2', 'samesalt', 16)
    assert.notEqual(hash5, hash6)

    hash = await cipheringArgon.hasher('secret', cipheringArgon.generateSalt(4), 16)
    assert.equal(16 * 2, hash.length)

    hash = await cipheringArgon.hasher('secret', cipheringArgon.generateSalt(4), 8)
    assert.equal(8 * 2, hash.length)

    const encrypted = await cipheringArgon.encrypt('secret data', 'aes-256-ctr')
    const decrypted = await cipheringArgon.decrypt(encrypted)
    assert.equal(decrypted, 'secret data')
  })
})

describe(`cryptographical integrity `, function() {
  it(`proper salt generation length for both kdf functions`, async () => {
    assert.equal(16 * 2, cipheringPbkdf2.generateSalt(16).length)
    assert.equal(16 * 2, cipheringArgon.generateSalt(16).length)

    return true
  })
  it(`salts must be generated randomly`, async () => {
    let newSalt = cipheringPbkdf2.generateSalt(16)
    let oldSalt = newSalt
    newSalt = cipheringPbkdf2.generateSalt(16)

    assert.notEqual(newSalt, oldSalt)

    return true
  })
  it(`different cipher-chain instances but same options should be able to decrypt both data identically`, async () => {
    const instance1 = new cipherChain({
      secret: 'secret123',
      saltLength: 4,
      options: {
        rounds: 1
      }
    })
    const instance2 = new cipherChain({
      secret: 'secret123',
      saltLength: 4,
      options: {
        rounds: 1
      }
    })
    await instance1.ready()
    await instance2.ready()
    let instance1Encryption = await instance1.encrypt('secret data', 'aes-256-gcm')
    let instance2Decryption = await instance2.decrypt(instance1Encryption)
    assert.equal(instance2Decryption, 'secret data')

    return true
  })
  it(`two encrypted results with the same secret and different salt should be unique`, async () => {
    let newHash = await cipheringPbkdf2.encrypt('secret data', 'aes-256-ctr')
    let oldHash = newHash
    newHash = await cipheringPbkdf2.encrypt('secret data', 'aes-256-ctr')

    assert.notEqual(newHash, oldHash)

    newHash = await cipheringArgon.encrypt('secret data', 'aes-256-ctr')
    oldHash = newHash
    newHash = await cipheringArgon.encrypt('secret data', 'aes-256-ctr')

    assert.notEqual(newHash, oldHash)

    return true
  })
})

describe(`algorithm integrity`, function() {
  for (let ciphername of crypto.getCiphers()) {
    if (bannedCiphers.includes(ciphername)) {
      continue
    }
    it(`${ciphername}`, async () => {
      await cipheringPbkdf2.ready()
      let encrypted = await cipheringPbkdf2.encrypt('secret data', ciphername)
      let decrypted = await cipheringPbkdf2.decrypt(encrypted)
      assert.equal(decrypted, 'secret data')

      await cipheringArgon.ready()
      encrypted = await cipheringArgon.encrypt('secret data', ciphername)
      decrypted = await cipheringArgon.decrypt(encrypted)
      assert.equal(decrypted, 'secret data')

      encrypted = await cipheringPbkdf2.encrypt({ secret: true }, ciphername)
      decrypted = await cipheringPbkdf2.decrypt(encrypted)
      assert.deepEqual(decrypted, { secret: true })

      encrypted = await cipheringArgon.encrypt({ secret: true }, ciphername)
      decrypted = await cipheringArgon.decrypt(encrypted)
      assert.deepEqual(decrypted, { secret: true })

      return true
    })
  }
})

describe(`algorithm chain integrity`, function() {
  let chains = []

  const cipherperpart = 4
  let ciphercount = 0
  let tempchain = []
  for (let ciphername of crypto.getCiphers()) {
    if (bannedCiphers.includes(ciphername)) {
      continue
    }
    tempchain.push(ciphername)
    ciphercount++
    if (cipherperpart == ciphercount) {
      chains.push(tempchain)
      tempchain = []
      ciphercount = 0
    }
  }

  if (tempchain.length >= 1) {
    tempchain.push(chains[0][0], chains[0][1], chains[0][2])
    chains.push(tempchain)
  }

  for (let chain of chains) {
    it(chain.join(' -> '), async () => {
      await cipheringPbkdf2.ready()
      let encrypted = await cipheringPbkdf2.encrypt('secret data', chain)
      let decrypted = await cipheringPbkdf2.decrypt(encrypted)
      assert.equal(decrypted, 'secret data')

      await cipheringArgon.ready()
      encrypted = await cipheringArgon.encrypt('secret data', chain)
      decrypted = await cipheringArgon.decrypt(encrypted)
      assert.equal(decrypted, 'secret data')

      encrypted = await cipheringPbkdf2.encrypt({ secret: true }, chain)
      decrypted = await cipheringPbkdf2.decrypt(encrypted)
      assert.deepEqual(decrypted, { secret: true })

      encrypted = await cipheringArgon.encrypt({ secret: true }, chain)
      decrypted = await cipheringArgon.decrypt(encrypted)
      assert.deepEqual(decrypted, { secret: true })

      return true
    })
  }
})
