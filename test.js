const cipherChain = require('../../cipher-chain')

;(async () => {
  const cipherchain = new cipherChain({
    secret: 'uber secret',
    kdf: 'md5',
    saltLength: 512
  })
  // Encrypt/Decrypt individually
  // console.log('Encrypting: ', 'secret data')
  // for (let cipher in cipherchain.ciphers) {
  //   console.log('\n-', cipher)
  //   let encrypted = await cipherchain.encrypt({ yeet: 123 }, cipher)
  //   let decrypted = await cipherchain.decrypt(encrypted)
  //   console.log('decrypted: ', decrypted)
  // }

  // Encrypt/Decrypt chain
  let encrypted = await cipherchain.encrypt(`I love you Aaron :)`, ['aes-256-cbc'])
  console.log('encrypted: ', encrypted)
  let decrypted = await cipherchain.decrypt(encrypted)
  console.log('decrypted: ', decrypted)
})()
