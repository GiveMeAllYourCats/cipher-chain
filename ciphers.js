const crypto = require('crypto')
const os = require('os')
const path = require('path')
const debug = require('debug')('cipherchain:ciphers')

const cachefile = path.join(os.tmpdir(), 'cipherchain.json')
let ciphers = false

const cache = require('node-file-cache').create({
  file: cachefile,
  life: 3600 * 24 * 1
})

const bytes = amount => {
  return crypto.randomBytes(amount).toString('hex')
}

const tryCipher = async (cipher, tryKey, tryIv, options = {}) => {
  let status = true
  let cipherIv
  try {
    cipherIv = crypto.createCipheriv(cipher, tryKey, tryIv, options)
  } catch (e) {
    status = String(e)
      .split('\n')[0]
      .split(': ')[1]
  }

  return status
}

const findKeyAndIv = async cipher => {
  const tries = []
  for (let i = 0; i <= 32; i++) {
    tries.push(i)
  }

  let foundKeyLength = false
  let foundIvLength = false
  let foundAuthTagLength = false
  let options = {}

  // Get IV Length
  for (let trylength of tries) {
    let tryIv = bytes(trylength)
    let tryKey = bytes(12)
    let result = await tryCipher(cipher, tryKey, tryIv)
    if (result == `authTagLength required for ${cipher}`) {
      options = {
        authTagLength: 16
      }
      foundAuthTagLength = 16
    }
    result = await tryCipher(cipher, tryKey, tryIv, options)

    if (result != 'Invalid IV length') {
      foundIvLength = trylength
    }

    if (result != 'Invalid IV length' && result != 'Invalid key length' && result != true) {
      throw new Error(result)
    }
  }

  // Get KEY Length
  for (let trylength of tries) {
    let tryIv = bytes(foundIvLength)
    let tryKey = bytes(trylength)
    const result = await tryCipher(cipher, tryKey, tryIv, options)
    if (result != 'Invalid key length') {
      foundKeyLength = trylength
    }

    if (result != 'Invalid IV length' && result != 'Invalid key length' && result != true) {
      throw new Error(result)
    }
  }

  return [foundKeyLength, foundIvLength, foundAuthTagLength]
}

module.exports = async () => {
  if (!ciphers) {
    ciphers = cache.get('ciphers')

    if (cache.get('ciphers') === null) {
      debug('rebuilding cipher list...')
      ciphers = {}
      let id = 0
      for (let cipher of crypto.getCiphers()) {
        if (cipher === 'aes-256-cbc') {
          continue
        }
        const [key, iv, authTagLength] = await findKeyAndIv(cipher)
        ciphers[cipher] = {
          key,
          iv,
          authTagLength,
          id
        }
        id++
      }
    }
    cache.set('ciphers', ciphers)
  }

  if (typeof ciphers != 'object') {
    throw new Error('failed building ciphers list')
  }

  if (ciphers.length <= 10) {
    throw new Error('ciphers list integrity failure')
  }

  // UNSUPPORTED :(
  delete ciphers['aes-128-xts']
  delete ciphers['aes-256-xts']
  delete ciphers['aes-wrap']
  delete ciphers['aes128-wrap']
  delete ciphers['aes192-wrap']
  delete ciphers['aes256-wrap']
  delete ciphers['des3-wrap']
  delete ciphers['id-aes128-wrap']
  delete ciphers['id-aes192-wrap']
  delete ciphers['id-aes256-wrap']
  delete ciphers['id-smime-alg-CMS3DESwrap']

  return ciphers
}
