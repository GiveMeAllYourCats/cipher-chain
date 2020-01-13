let crypto
try {
  crypto = require('crypto')
} catch (err) {
  console.log('crypto support is disabled!')
  process.exit()
}
const fs = require('fs')
const blake2 = require('blake2')
const _ = require('lodash')
const glob = require('glob')
const path = require('path')
const argon2 = require('argon2')

class CipherChain {
  constructor(options) {
    return new Promise(async resolve => {
      // Setup instance options
      const standardKdfSettings = {
        use: 'argon2',
        options: {
          argon2: {
            type: argon2.argon2i,
            memoryCost: 1024 * 4, // 4mb
            timeCost: 4
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
      this.doHmac = _.get(options, 'hmacVerify', true)
      this.secret = _.get(options, 'secret')
      this.hmacAlgorithm = _.get(options, 'hmacAlgorithm', 'sha512')
      this.concurrentFiles = _.get(options, 'concurrentFiles', 100)

      if (!_.get(options, 'chain')) {
        throw new Error('Must specify chain in instance options')
      }

      if (typeof options.chain === 'string') {
        options.chain = [options.chain]
      }
      this.chain = options.chain

      this.secretFile = _.get(options, 'secretFile')
      if (this.secretFile) {
        if (!fs.existsSync(this.secretFile)) {
          this.secret = crypto.randomBytes(256).toString('hex')
          fs.writeFileSync(this.secretFile, this.secret)
        } else {
          this.secret = fs
            .readFileSync(this.secretFile)
            .toString('ascii')
            .replace(/\s/g, '')
        }
      }

      if (!this.secret) {
        throw new Error('No secret or secretfile was defined.')
      }

      this.ciphers = await require('./ciphers.js')()
      for (let index in this.chain) {
        const algorithm = this.chain[index]
        const cipher = this.ciphers[algorithm]
        this.chain[index] = {
          cipher: cipher,
          kdf: await this.generateSecret(this.secret, this.kdf.salt, cipher.key)
        }
      }

      return resolve(this)
    })
  }

  async encrypt(plaintext) {
    for (let chain of this.chain) {
      plaintext = await this.encryptInternal(plaintext, chain)
    }

    let hmac = 0
    if (this.doHmac) {
      hmac = await this.hmac(plaintext)
    }

    return `@CC2-${hmac}:${plaintext}`
  }

  async decrypt(encrypted) {
    if (encrypted.slice(0, 5) != '@CC2-') {
      throw new Error(`Not a encrypted cipher-chain string`)
    }

    encrypted = encrypted.replace('@CC2-', '')
    let encryptedMacCheck = encrypted.split(':')
    encryptedMacCheck.shift()
    encryptedMacCheck = encryptedMacCheck.join(':')
    const checkHmac = await this.hmac(encryptedMacCheck)

    const encryptedHmac = encrypted.split(':')[0]
    encrypted = encrypted.replace(`${encryptedHmac}:`, '')

    if (checkHmac != 0 && encryptedHmac != 0) {
      if (!crypto.timingSafeEqual(Buffer.from(encryptedHmac), Buffer.from(checkHmac))) {
        throw new Error('HMAC verification failed')
      }
    }

    while (encrypted.split(':').length == 6) {
      encrypted = await this.decryptInternal(encrypted)
    }

    return encrypted
  }

  async encryptDirectory(dirpatt) {
    const cipherChainFile = path.join(dirpatt, '.cipher-chain')
    if (fs.existsSync(cipherChainFile)) {
      throw new Error(`Directory '${dirpatt}' already encrypted`)
    }
    const files = glob.sync('**/*', { cwd: dirpatt })
    const filenames = []
    const promises = files.map(async file => {
      const data = await this.encrypt(file)
      const hashedFilename = crypto
        .createHmac('sha1', this.secret)
        .update(file)
        .digest('hex')
      const fileToEncrypt = path.join(dirpatt, file)
      filenames.push({
        data,
        hash: hashedFilename
      })
      await this.encryptFile(fileToEncrypt)
      fs.renameSync(fileToEncrypt, path.join(dirpatt, hashedFilename))
      return true
    })
    await Promise.all(promises)

    fs.writeFileSync(cipherChainFile, JSON.stringify(filenames))
  }

  async decryptDirectory(dirpatt) {
    const cipherChainFile = path.join(dirpatt, '.cipher-chain')
    if (!fs.existsSync(cipherChainFile)) {
      throw new Error(`Directory '${dirpatt}' is not encrypted (.cipher-chain file not found!)`)
    }

    const filenames = JSON.parse(fs.readFileSync(cipherChainFile))
    const promises = filenames.map(async filename => {
      const fileToDecrypt = path.join(dirpatt, filename.hash)
      if (fs.existsSync(fileToDecrypt)) {
        await this.decryptFile(fileToDecrypt)
        const newFilename = await this.decrypt(filename.data)
        fs.renameSync(fileToDecrypt, path.join(dirpatt, newFilename))
      }

      return true
    })
    await Promise.all(promises)
    fs.unlinkSync(cipherChainFile)
  }

  async encryptFile(file) {
    const data = fs.readFileSync(file, 'base64')
    const encryptedData = await this.encrypt(data)
    fs.writeFileSync(file, encryptedData)
    return true
  }

  async decryptFile(file) {
    const data = fs.readFileSync(file, 'utf-8')
    const decryptedData = await this.decrypt(data)
    fs.writeFileSync(file, Buffer.from(decryptedData, 'base64'))
    return true
  }

  async encryptInternal(plaintext, chain) {
    const iv = this.randomBytes(chain.cipher.iv)
    const cipher = await this.cipher(plaintext, chain.cipher.cipher, chain.kdf.hash, iv)
    return `${chain.cipher.id}:${cipher.autoPadding}:${cipher.authtag}:${chain.kdf.salt}:${iv}:${cipher.encrypted}`
  }

  async decryptInternal(encrypted) {
    const encryptedSplit = encrypted.split(':')

    if (encryptedSplit.length === 1) {
      return encrypted
    }

    const algorithm = _.find(this.ciphers, e => {
      return e.id == encryptedSplit[0]
    })
    const autoPadding = !!encryptedSplit[1]
    const authTag = encryptedSplit[2]
    const kdfSalt = encryptedSplit[3]
    const iv = encryptedSplit[4]
    const encryption = encryptedSplit[5]
    if (!algorithm) {
      throw new Error(`Could not find algorithm id '${encryptedSplit[0]}'`)
    }
    const cipher = this.ciphers[algorithm.cipher]
    const secret = await this.generateSecret(this.secret, kdfSalt, cipher.key)
    const options = {}
    return await this.decipher(encryption, algorithm, secret, iv, autoPadding, authTag, options)
  }

  async cipher(text, algorithm, key, iv, options = {}) {
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

  async decipher(text, algorithm, key, iv, autoPadding, authtag = 0, options = {}) {
    const decipher = crypto.createDecipheriv(algorithm.cipher, key.hash, iv, options)
    decipher.setAutoPadding(autoPadding)
    if (authtag != 0) {
      decipher.setAuthTag(Buffer.from(authtag, 'hex'))
    }
    let decrypted = decipher.update(text, 'hex', 'binary')

    try {
      decrypted += decipher.final('binary')
    } catch (e) {
      if (e.code === 'ERR_OSSL_EVP_BAD_DECRYPT') {
        return e.code
      } else {
        throw new Error(e)
      }
    }

    return decrypted
  }

  randomBytes(amount) {
    return crypto.randomBytes(amount).toString('hex')
  }

  async hmac(string, key, algorithm) {
    if (!this.doHmac) {
      return 0
    }
    if (!key) {
      key = this.secret
    }
    if (!algorithm) {
      algorithm = this.hmacAlgorithm
    }
    const hmac = crypto
      .createHmac(algorithm, key)
      .update(string)
      .digest('hex')
    return hmac
  }

  async generateSecret(secret, salt, keylength) {
    let hash
    const options = this.kdf.options[this.kdf.use]
    if (this.kdf.use === 'pbkdf2') {
      if (!salt) {
        salt = this.randomBytes(32)
      }
      hash = crypto.pbkdf2Sync(secret, salt, options.rounds, parseInt(keylength), options.hash).toString('hex')
    } else if (this.kdf.use === 'blake2') {
      if (!salt) {
        salt = this.randomBytes(32)
      }
      hash = blake2
        .createHash('blake2b', { digestLength: keylength })
        .update(Buffer.from(`${secret}:${salt}`))
        .digest('hex')
    } else if (this.kdf.use === 'scrypt') {
      if (!salt) {
        salt = this.randomBytes(32)
      }
      hash = crypto.scryptSync(secret, salt, keylength).toString('hex')
    } else if (this.kdf.use === 'argon2') {
      if (!salt) {
        salt = this.randomBytes(32)
      }
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

    return { salt, hash, kdf: this.kdf.use }
  }
}

module.exports = CipherChain
