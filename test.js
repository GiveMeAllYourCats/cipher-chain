const cipherChain = require('../../cipher-chain')

;(async () => {
  const cipherchain = new cipherChain('uber secret')
  // Encrypt/Decrypt individually
  console.log('Encrypting: ', 'secret data')
  for (let cipher in cipherchain.ciphers) {
    console.log('\n-', cipher)
    let encrypted = await cipherchain.encrypt({ yeet: 123 }, cipher)
    let decrypted = await cipherchain.decrypt(encrypted)
    console.log('decrypted: ', decrypted)
  }
})()
