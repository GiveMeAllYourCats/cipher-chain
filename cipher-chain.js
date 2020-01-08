const crypto = require('crypto')
const _ = require('lodash')
const argon2 = require('argon2')
const debug = {
  encrypt: require('debug')('ciphering:encrypt'),
  decrypt: require('debug')('ciphering:decrypt'),
  chainDecrypt: require('debug')('ciphering:chain:decrypt'),
  chainEncrypt: require('debug')('ciphering:chain:encrypt'),
  warning: require('debug')('ciphering:warning')
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

    this.ciphers = {
      'aes-256-gcm': {
        iv: 16,
        key: 16
      },
      'aes-128-gcm': {
        iv: 16,
        key: 8
      },
      'aes-128-ctr': {
        iv: 8,
        key: 8
      },
      'aes-256-cbc': {
        iv: 8,
        key: 16
      },
      'aes-256-ctr': {
        iv: 8,
        key: 16
      },
      'aes-128-cbc': {
        iv: 8,
        key: 8
      },
      'bf-cbc': {
        iv: 4,
        key: 16
      },
      'aria-256-gcm': {
        iv: 16,
        key: 16
      },
      'aria-256-ctr': {
        iv: 8,
        key: 16
      },
      'aria-192-gcm': {
        iv: 16,
        key: 12
      },
      'aria-192-cbc': {
        iv: 8,
        key: 12
      },
      'aria-192-ctr': {
        iv: 8,
        key: 12
      },
      'camellia-192-cbc': {
        iv: 8,
        key: 12
      },
      'camellia-192-ctr': {
        iv: 8,
        key: 12
      },
      'camellia-256-cbc': {
        iv: 8,
        key: 16
      },
      'cast-cbc': {
        iv: 4,
        key: 16
      },
      'cast5-cbc': {
        iv: 4,
        key: 16
      }
    }

    this.kdfs = {
      pbkdf2: {
        name: 'pbkdf2',
        options: {
          rounds: 20000,
          hash: 'sha512'
        }
      },
      argon2: {
        name: 'argon2',
        options: {
          type: argon2.argon2i,
          timeCost: 1,
          memoryCost: 4096,
          saltLength: 16
        }
      }
    }

    this.kdf = this.kdfs['pbkdf2']
    if (_.get(options, 'kdf')) {
      this.kdf = this.kdfs[options.kdf]
    }

    if (_.get(options, 'options')) {
      this.kdf.options = _.merge({}, this.kdf.options, options.options)
    }

    if (!this.kdf) {
      throw new Error(`${options.kdf} is not a valid hashing algorithm`)
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

    if (typeof algorithm == 'object') {
      this.chain = algorithm
      return await this.chainEncrypt(plaintext)
    }

    const salt = this.generateSalt(16)
    const iv = this.generateSalt(this.ciphers[algorithm].iv)
    const secret = await this.hasher(this.secret, salt, this.ciphers[algorithm].key)

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
    debug.encrypt(`${plaintext} -> ${encrypted} [${algorithm}]`)

    return result
  }

  async decrypt(encrypted) {
    if (this.chain) {
      if (!this.decryptChainInProgress) {
        this.decryptChainInProgress = true
        const result = await this.chainDecrypt(encrypted)
        this.chain = false
        this.decryptChainInProgress = false
        return result
      }
    }
    const decryptionObject = Buffer.from(encrypted, 'base64')
      .toString('utf8')
      .split(':')

    const version = decryptionObject[0] // In the future with updates, can do something with version
    const algorithm = decryptionObject[1]
    const salt = decryptionObject[2]
    const iv = decryptionObject[3]
    const authtag = decryptionObject[4]
    encrypted = decryptionObject[5]
    const secret = await this.hasher(this.secret, salt, this.ciphers[algorithm].key)

    let decrypted = false

    const decipher = crypto.createDecipheriv(algorithm, secret, iv)
    if (authtag != 0) {
      decipher.setAuthTag(Buffer.from(authtag, 'hex'))
    }
    decrypted = decipher.update(encrypted, 'hex', 'utf8')
    decrypted += decipher.final('utf8')

    debug.decrypt(`${encrypted} -> ${decrypted} [${algorithm}]`)

    try {
      decrypted = JSON.parse(decrypted)
    } catch (e) {
      // yoat
    }

    return decrypted
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
            hashLength: keylength
          },
          this.kdf.options
        )
      )
      return argon2output.toString('hex')
    }
  }
}

module.exports = Ciphering
