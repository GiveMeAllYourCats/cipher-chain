const crypto = require('crypto')
const _ = require('lodash')
const isBase64 = require('is-base64')
const argon2 = require('argon2')

const ciphers = require('./ciphers.js')

const debug = {
  encrypt: require('debug')('cipherchain:encrypt'),
  decrypt: require('debug')('cipherchain:decrypt'),
  chainDecrypt: require('debug')('cipherchain:chain:decrypt'),
  chainEncrypt: require('debug')('cipherchain:chain:encrypt'),
  warning: require('debug')('cipherchain:warning'),
  test: require('debug')('cipherchain:test')
}

class Ciphering {
  constructor(options) {
    if (typeof options == 'string') {
      this.secret = options
    } else {
      this.secret = options.secret
    }
    this.version = 1
    this.chain = false
    this.ciphers = ciphers
    this.saltLength = 6
    if (_.get(options, 'saltLength')) {
      this.saltLength = parseInt(options.saltLength)
    }
    this.salt = false
    if (_.get(options, 'salt')) {
      this.salt = options.salt
    }

    this.kdfs = {
      pbkdf2: {
        name: 'pbkdf2',
        options: {
          rounds: 10000,
          hash: 'sha512'
        }
      },
      argon2: {
        name: 'argon2',
        options: {
          type: argon2.argon2i,
          timeCost: 3,
          memoryCost: 1024
        }
      }
    }

    this.kdf = this.kdfs.argon2
    if (_.get(options, 'kdf')) {
      this.kdf = this.kdfs[options.kdf]
    }

    if (_.get(options, 'options')) {
      this.kdf.options = _.merge({}, this.kdf.options, options.options)
    }

    if (!this.kdf) {
      if (!crypto.getHashes().includes(options.kdf)) {
        throw new Error(`${options.kdf} is not a valid hashing method`)
      } else {
        if (!_.get(this.kdfs, options.kdf)) {
          this.kdfs[options.kdf] = {
            name: options.kdf
          }
          this.kdf = this.kdfs[options.kdf]
        }
      }
    }
  }

  generateSalt(amount) {
    return crypto.randomBytes(amount).toString('hex')
  }

  async chainDecrypt(encrypted) {
    const chain = this.chain.reverse()

    let decrypted = encrypted
    let decryptedBefore = encrypted

    for (let algorithm of chain) {
      decryptedBefore = encrypted
      decrypted = await this.decrypt(decrypted, algorithm)

      let printdecrypted = decrypted
      if (typeof decrypted === 'object') {
        printdecrypted = JSON.stringify(decrypted)
      }
      debug.chainDecrypt(`${decryptedBefore} -> ${printdecrypted}`)
    }

    return decrypted
  }

  async chainEncrypt(plaintext) {
    const chain = this.chain

    let encrypted = plaintext
    let encryptedBefore = encrypted

    for (let algorithm of chain) {
      encryptedBefore = encrypted
      encrypted = await this.encrypt(encrypted, algorithm)
    }

    return encrypted
  }

  async encrypt(plaintext, algorithm) {
    if (typeof plaintext == 'object') {
      plaintext = JSON.stringify(plaintext)
    }
    if (typeof plaintext == 'number') {
      plaintext = String(plaintext)
    }

    if (typeof algorithm == 'object') {
      this.chain = algorithm
      return await this.chainEncrypt(plaintext)
    }

    const salt = this.generateSalt(this.saltLength)
    const iv = this.generateSalt(this.ciphers[algorithm].iv)
    const secret = await this.hasher(this.secret, salt, this.ciphers[algorithm].key)

    debug.encrypt(`-- Encrypt: ${algorithm} --`)
    debug.encrypt(`iv: ${iv} (${iv.length})`)
    debug.encrypt(`secret: ${secret} (${secret.length})`)
    debug.encrypt(`hashsalt: ${salt} (${salt.length})`)
    const cipher = crypto.createCipheriv(algorithm, secret, iv)
    let encrypted = cipher.update(plaintext, 'utf8', 'hex')
    encrypted += cipher.final('hex')

    let authtag = 0
    try {
      authtag = cipher.getAuthTag().toString('hex')
    } catch (e) {
      if (e.code === 'ERR_CRYPTO_INVALID_STATE') {
        debug.warning(`will not use authtag for this algorithm: ${algorithm}`)
      } else {
        throw new Error(e)
      }
    }

    const protocolString = `${this.version}:${algorithm}:${salt}:${iv}:${authtag}:${encrypted}`
    const result = Buffer.from(protocolString).toString('base64')
    debug.encrypt(`plaintext: ${plaintext}`)
    debug.encrypt(`encrypted: ${result}`)

    return result
  }

  async decrypt(encrypted) {
    if (this.chain && !this.decryptChainInProgress) {
      this.decryptChainInProgress = true
      const result = await this.chainDecrypt(encrypted)
      this.chain = false
      this.decryptChainInProgress = false
      return result
    }

    let decryptionObject
    if (isBase64(encrypted, { allowEmpty: false })) {
      decryptionObject = Buffer.from(encrypted, 'base64')
    }

    decryptionObject = decryptionObject.toString('utf8')

    if (typeof decryptionObject !== 'string') {
      throw new Error(`integrity error (error: #1)`)
    }

    if (decryptionObject.indexOf(':') === -1) {
      throw new Error(`integrity error (error: #2)`)
    }

    decryptionObject = decryptionObject.split(':')

    if (decryptionObject.length !== 6) {
      throw new Error(`integrity error (error: #3)`)
    }

    const version = decryptionObject[0] // In the future with updates, can do something with version
    const algorithm = decryptionObject[1]
    const salt = decryptionObject[2]
    const iv = decryptionObject[3]
    const authtag = decryptionObject[4]
    encrypted = decryptionObject[5]
    const secret = await this.hasher(this.secret, salt, this.ciphers[algorithm].key)
    debug.decrypt(`-- Decrypt: ${algorithm} --`)
    debug.decrypt(`iv: ${iv} (${iv.length})`)
    debug.decrypt(`secret: ${secret} (${secret.length})`)
    debug.decrypt(`hashsalt: ${salt} (${salt.length})`)
    debug.decrypt(`version: ${version}`)
    debug.decrypt(`authtag: ${authtag}`)
    debug.decrypt(`encrypted: ${encrypted} (${encrypted.length})`)

    let decrypted = false

    const decipher = crypto.createDecipheriv(algorithm, secret, iv)
    if (authtag != 0) {
      decipher.setAuthTag(Buffer.from(authtag, 'hex'))
    }
    decrypted = decipher.update(encrypted, 'hex', 'utf8')

    try {
      decrypted += decipher.final('utf8')
    } catch (e) {
      if (e.code === 'ERR_OSSL_EVP_BAD_DECRYPT') {
        throw new Error('Decryption failed, possible due to wrong secret or salt')
      } else {
        throw new Error(e)
      }
    }

    debug.decrypt(`decrypted: ${decrypted}`)

    if (this.isJson(decrypted)) {
      decrypted = JSON.parse(decrypted)
    }

    return decrypted
  }

  isJson(testjson) {
    try {
      testjson = JSON.parse(testjson)
    } catch (e) {
      return false
    }
    return true
  }

  async hasher(secret, salt, keylength) {
    keylength = parseInt(keylength)
    if (this.kdf.name === 'pbkdf2') {
      return crypto.pbkdf2Sync(secret, salt, this.kdf.options.rounds, keylength, this.kdf.options.hash).toString('hex')
    } else if (this.kdf.name === 'argon2') {
      const argon2output = await argon2.hash(
        secret,
        _.merge(
          {},
          {
            raw: true,
            hashLength: keylength,
            salt: Buffer.from(salt)
          },
          this.kdf.options
        )
      )
      return argon2output.toString('hex')
    } else {
      const hash = crypto
        .createHash(this.kdf.name)
        .update(`${salt}:${secret}`)
        .digest('hex')
        .slice(0, keylength * 2)

      return hash
    }
  }
}

module.exports = Ciphering
