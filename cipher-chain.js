let crypto
try {
  crypto = require('crypto')
} catch (err) {
  throw new Error('crypto support is disabled!')
}
const fs = require('fs')
const blake2 = require('blake2')
const _ = require('lodash')
const glob = require('glob')
const zxcvbn = require('zxcvbn')
const path = require('path')
const argon2 = require('argon2')
const zlib = require('zlib')
const asyncPool = require('tiny-async-pool')
const version = require('./package.json').version.split('.')[0]

class CipherChain {
  constructor(options) {
    return new Promise(async resolve => {
      // Setup instance options
      const standardKdfSettings = {
        use: 'argon2',
        saltLength: 12,
        options: {
          argon2: {
            type: argon2.argon2i,
            memoryCost: 1024 * 8,
            timeCost: 6
          },
          pbkdf2: {
            rounds: 10000,
            hash: 'sha512'
          }
        }
      }
      this.kdf = _.get(options, 'kdf', standardKdfSettings)
      this.kdf = _.merge({}, standardKdfSettings, this.kdf)
      this.kdfs = ['blake2', 'argon2', 'pbkdf2', 'scrypt']

      this.autoPadding = _.get(options, 'autoPadding', true)
      this.timingSafeCheck = _.get(options, 'timingSafeCheck', true)
      this.compressData = _.get(options, 'compressData', true)
      this.enableSecurityRequirements = _.get(options, 'enableSecurityRequirements', true)
      this.concurrentFiles = _.get(options, 'concurrentFiles', 20)
      this.maxEncryptFileInBytes = _.get(options, 'maxEncryptFileInBytes', 170000000)
      this.hmacAlgorithm = _.get(options, 'hmacAlgorithm', 'sha512')

      if (!_.get(options, 'chain')) {
        throw new Error('Must specify chain in instance options')
      }

      if (typeof options.chain === 'string') {
        options.chain = [options.chain]
      }
      this.chain = options.chain

      this.secret = _.get(options, 'secret')

      if (!this.secret) {
        throw new Error('No secret or secretfile was defined.')
      }

      if (!Array.isArray(this.secret) && this.chain.length >= 2) {
        throw new Error('Secret needs to be a array')
      }

      if (!Array.isArray(this.secret)) {
        this.secret = [this.secret]
      }

      if (this.secret.length != this.chain.length) {
        throw new Error('Secret array needs to have as much elements as the chain option')
      }

      const duplicatePasswords = _.filter(this.secret, (val, i, iteratee) => _.includes(iteratee, val, i + 1))
      if (duplicatePasswords.length >= 1) {
        throw new Error('Each secret needs to be unique')
      }

      if (this.enableSecurityRequirements) {
        let i = 1
        for (let val of this.secret) {
          i++
          const zxcvbnResult = zxcvbn(val)
          if (zxcvbnResult.score <= 2) {
            throw new Error(`secret #${i} is a weak secret. ${zxcvbnResult.feedback.suggestions.join(' ')}`)
          }
          if (val.length <= 23) {
            throw new Error(`secret #${i} is a weak secret. It's under 24 characters, you need ${24 - val.length} more characters`)
          }
        }
      }

      this.ciphers = await require('./ciphers.js')()
      for (let index in this.chain) {
        const algorithm = this.chain[index]
        const cipher = this.ciphers[algorithm]
        if (!cipher) {
          throw new Error(`Could not find cipher algorithm '${algorithm}'`)
        }
        this.chain[index] = {
          index: index,
          cipher: cipher,
          kdf: await this.generateSecret(this.secret[index], this.secretSalt, cipher.key)
        }
      }

      return resolve(this)
    })
  }

  async encrypt(plaintext) {
    for (let chain of this.chain) {
      plaintext = await this.encryptInternal(plaintext, chain)
    }

    const hmac = `${await this.hmac(plaintext, this.secret.join(''))}:`

    plaintext = `@CC${version}-${hmac}${plaintext}`

    if (this.compressData) {
      plaintext = zlib.deflateSync(plaintext).toString('base64')
    }

    return plaintext
  }

  async decrypt(encrypted) {
    try {
      encrypted = zlib.inflateSync(Buffer.from(encrypted, 'base64')).toString('utf-8')
    } catch (e) {}

    if (encrypted.slice(0, 5) != `@CC${version}-`) {
      throw new Error(`Not a encrypted cipher-chain version ${version} string`)
    }
    encrypted = encrypted.replace(`@CC${version}-`, '')

    let computedHmac = encrypted.split(':')[0]
    encrypted = encrypted.replace(computedHmac + ':', '')
    const hmac = `${await this.hmac(encrypted, this.secret.join(''))}`

    if (this.timingSafeCheck) {
      if (crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(computedHmac)) === false) {
        throw new Error('HMAC verification failed')
      }
    } else {
      if (hmac !== computedHmac) {
        throw new Error('HMAC verification failed')
      }
    }

    let index = this.chain.length - 1
    while (index != -1) {
      encrypted = await this.decryptInternal(encrypted, index)
      index--
    }

    return encrypted
  }

  async encryptDirectory(dirpatt) {
    const files = glob.sync(dirpatt, { nodir: true })
    const encryptFile = file =>
      new Promise(async resolve => {
        if (file.slice(file.length - 13) !== `.cipherchain${version}`) {
          await this.encryptFile(file)
        }
        return resolve()
      })
    await asyncPool(this.concurrentFiles, files, encryptFile)
  }

  async decryptDirectory(dirpatt) {
    const files = glob.sync(dirpatt, { nodir: true })
    const decryptFile = file =>
      new Promise(async resolve => {
        if (file.slice(file.length - 13) === `.cipherchain${version}`) {
          await this.decryptFile(file)
        }
        return resolve()
      })
    await asyncPool(this.concurrentFiles, files, decryptFile)
  }

  async encryptFile(file) {
    const stats = fs.statSync(file)
    const fileSizeInBytes = stats.size
    if (fileSizeInBytes >= this.maxEncryptFileInBytes) {
      throw new Error(
        `${file} is over ${fileSizeInBytes.toLocaleString()} bytes, maxEncryptFileInBytes is ${this.maxEncryptFileInBytes.toLocaleString()}`
      )
    }
    const data = Buffer.from(fs.readFileSync(file, 'base64'))
    const hashedFilename = `${this.randomBytes(64).toString('hex')}.cipherchain${version}`
    const fileData = `${file}\n${hashedFilename}\n${data}`
    const encryptedData = await this.encrypt(fileData)
    fs.writeFileSync(file, encryptedData)
    fs.renameSync(file, path.join(path.dirname(file), hashedFilename))
    return path.join(path.dirname(file), hashedFilename)
  }

  async decryptFile(file) {
    let data = fs.readFileSync(file, 'utf-8')
    const decryptedData = await this.decrypt(data)
    const fileData = decryptedData.split('\n')
    const newFilename = fileData[0]
    fs.writeFileSync(file, Buffer.from(fileData[2], 'base64'))
    fs.renameSync(path.join(path.dirname(file), fileData[1]), newFilename)

    return true
  }

  async encryptInternal(plaintext, chain) {
    const iv = this.randomBytes(chain.cipher.iv)
    const cipher = await this.cipher(plaintext, chain.cipher.cipher, chain.kdf.hash, iv)
    return `${cipher.authtag}:${chain.kdf.salt}:${iv}:${cipher.encrypted}`
  }

  async decryptInternal(encrypted, index) {
    const encryptedSplit = encrypted.split(':')

    const authTag = encryptedSplit[0]
    const kdfSalt = encryptedSplit[1]
    const iv = encryptedSplit[2]
    const encryption = encryptedSplit[3]
    const secret = await this.generateSecret(this.secret[index], kdfSalt, this.chain[index].cipher.key)
    return await this.decipher(encryption, this.chain[index].cipher, secret, iv, authTag)
  }

  async cipher(text, algorithm, key, iv) {
    const options = {}
    if (_.get(this.ciphers[algorithm], 'authTagLength') !== false) {
      options.authTagLength = this.ciphers[algorithm].authTagLength
    }
    const cipher = crypto.createCipheriv(algorithm, key, iv, options)
    cipher.setAutoPadding(this.autoPadding)
    let encrypted = cipher.update(text, 'binary', 'hex')
    encrypted += cipher.final('hex')

    let authtag = 0
    try {
      authtag = cipher.getAuthTag().toString('hex')
    } catch (e) {
      if (e.code === 'ERR_CRYPTO_INVALID_STATE') {
        // Will not use authtag for this algorithm
      } else {
        throw new Error(e)
      }
    }

    return {
      encrypted,
      authtag,
      autoPadding: this.autoPadding ? 1 : 0
    }
  }

  async decipher(text, algorithm, key, iv, authtag = 0, options = {}) {
    if (_.get(algorithm, 'authTagLength') !== false) {
      options.authTagLength = algorithm.authTagLength
    }
    const decipher = crypto.createDecipheriv(algorithm.cipher, key.hash, iv, options)
    decipher.setAutoPadding(this.autoPadding)
    if (authtag != 0) {
      decipher.setAuthTag(Buffer.from(authtag, 'hex'))
    }
    let decrypted = decipher.update(text, 'hex', 'binary')

    decrypted += decipher.final('binary')

    return decrypted
  }

  randomBytes(amount) {
    return crypto.randomBytes(amount).toString('hex')
  }

  async hmac(string, key) {
    return crypto
      .createHmac(this.hmacAlgorithm, key)
      .update(string)
      .digest('hex')
  }

  async generateSecret(secret, salt, keylength) {
    let hash
    const options = this.kdf.options[this.kdf.use]
    if (!salt) {
      salt = this.randomBytes(this.kdf.saltLength)
    }
    if (this.kdf.use === 'pbkdf2') {
      hash = crypto.pbkdf2Sync(secret, salt, options.rounds, parseInt(keylength), options.hash).toString('hex')
    } else if (this.kdf.use === 'blake2') {
      hash = blake2
        .createHash('blake2b', { digestLength: keylength })
        .update(Buffer.from(`${secret}:${salt}`))
        .digest('hex')
    } else if (this.kdf.use === 'scrypt') {
      hash = crypto.scryptSync(secret, salt, keylength).toString('hex')
    } else if (this.kdf.use === 'argon2') {
      const argon2output = await argon2.hash(
        secret,
        _.merge(
          {},
          {
            raw: true,
            hashLength: parseInt(keylength),
            salt: Buffer.from(salt)
          },
          options
        )
      )
      hash = argon2output.toString('hex')
    } else {
      throw new Error(`${this.kdf.use} is not a valid KDF`)
    }

    return { secret: secret, salt, hash, kdf: this.kdf.use }
  }
}

module.exports = CipherChain
