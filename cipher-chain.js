const crypto = require('crypto')
const path = require('path')
const fs = require('fs')
const _ = require('lodash')
const argon2 = require('argon2')
const base64regex = new RegExp('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$')

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

    this.secretFile = path.join(this.secret, 'cipher-chain.key')
    let isSecretDir = false
    try {
      isSecretDir = fs.lstatSync(this.secret).isDirectory()
    } catch (e) {}
    if (isSecretDir) {
      if (!fs.existsSync(this.secretFile)) {
        this.secret = crypto.randomBytes(4096).toString('hex')
        fs.writeFileSync(this.secretFile, this.secret)
      } else {
        this.secret = fs
          .readFileSync(this.secretFile)
          .toString('utf8')
          .replace(/\s/g, '')
      }
    }

    this.version = 1
    this.chain = false
    this.isReady = false
    this.saltLength = 4
    if (_.get(options, 'saltLength')) {
      this.saltLength = parseInt(options.saltLength)
    }

    this.ciphersList = false
    require('./ciphers.js')().then(list => {
      this.ciphersList = list
    })

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
          type: 'argon2i',
          timeCost: 3,
          memoryCost: 1024
        }
      }
    }

    this.kdf = this.kdfs.argon2
    if (_.get(options, 'kdf')) {
      this.kdf = this.kdfs[options.kdf]
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

    if (this.kdf.name === 'argon2') {
      if (!eval(`argon2.${this.kdf.options.type}`)) {
        throw new Error(`${this.kdf.options.type} is not a valid argon2 type`)
      }
      this.kdf.options.type = eval(`argon2.${this.kdf.options.type}`)
    }

    this.kdf.options = _.merge({}, this.kdf.options, _.get(options, 'options', {}))
  }

  generateSalt(amount) {
    return crypto.randomBytes(amount).toString('hex')
  }

  async chainDecrypt(encrypted) {
    let decrypted = encrypted
    let decryptedBefore = encrypted
    let chainNotEmpty = true

    while (chainNotEmpty) {
      decryptedBefore = encrypted
      decrypted = await this.decrypt(decrypted)

      let printdecrypted
      if (typeof decrypted === 'object') {
        printdecrypted = JSON.stringify(decrypted)
      }
      debug.chainDecrypt(`${decryptedBefore} -> ${printdecrypted}`)
      if (base64regex.test(decrypted) === false) {
        chainNotEmpty = false
      }
    }

    return decrypted
  }

  async ready() {
    if (this.isReady) {
      return true
    }
    return new Promise((resolve, reject) => {
      this.readyCheck = setInterval(() => {
        if (typeof this.ciphersList == 'object') {
          clearInterval(this.readyCheck)
          this.isReady = true
          return resolve(true)
        }
      })
    })
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

    if (!this.isReady) {
      throw new Error('cipher-chain is not ready, please write "await cipherchaininstance.ready()" after instance creation')
    }

    if (!this.ciphersList[algorithm]) {
      throw new Error(`Cannot find cipher algorithm: ${algorithm}`)
    }

    const salt = this.generateSalt(this.saltLength)
    const iv = this.generateSalt(this.ciphersList[algorithm].iv)
    const secret = await this.hasher(this.secret, salt, this.ciphersList[algorithm].key)

    debug.encrypt(`-- Encrypt: ${algorithm} --`)
    debug.encrypt(`iv: ${iv} (${iv.length})`)
    debug.encrypt(`secret: ${secret} (${secret.length})`)
    debug.encrypt(`hashsalt: ${salt} (${salt.length})`)
    let options = {}
    if (_.get(this.ciphersList[algorithm], 'authTagLength') !== false) {
      options.authTagLength = this.ciphersList[algorithm].authTagLength
    }
    const cipher = crypto.createCipheriv(algorithm, secret, iv, options)
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

    algorithm = this.ciphersList[algorithm].id

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

    if (!this.isReady) {
      throw new Error('cipher-chain is not ready, please write "await cipherchaininstance.ready()" after instance creation')
    }

    let decryptionObject = Buffer.from(encrypted, 'base64').toString('utf8')

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
    let algorithm = _.find(this.ciphersList, o => {
      return o.id == decryptionObject[1]
    })

    if (!algorithm) {
      throw new Error(`Cannot find cipher algorithm with id: ${decryptionObject[1]}`)
    }

    const salt = decryptionObject[2]
    const iv = decryptionObject[3]
    const authtag = decryptionObject[4]
    encrypted = decryptionObject[5]
    const secret = await this.hasher(this.secret, salt, algorithm.key)
    debug.decrypt(`-- Decrypt: ${algorithm.cipher} --`)
    debug.decrypt(`iv: ${iv} (${iv.length})`)
    debug.decrypt(`secret: ${secret} (${secret.length})`)
    debug.decrypt(`hashsalt: ${salt} (${salt.length})`)
    debug.decrypt(`version: ${version}`)
    debug.decrypt(`authtag: ${authtag}`)
    debug.decrypt(`encrypted: ${encrypted} (${encrypted.length})`)

    let decrypted = false

    let options = {}
    if (_.get(algorithm, 'authTagLength') !== false) {
      options.authTagLength = algorithm.authTagLength
    }
    const decipher = crypto.createDecipheriv(algorithm.cipher, secret, iv, options)
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
