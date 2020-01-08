<p align="center"><img src="https://i.imgur.com/wl9gbog.png" /></p>

# cipher-chain

[![HitCount](http://hits.dwyl.io/michaeldegroot/cipher-chain.svg)](http://hits.dwyl.io/michaeldegroot/cipher-chain)
[![Package quality](https://packagequality.com/shield/cipher-chain.svg)](https://packagequality.com/#?package=cipher-chain)
[![Build Status](https://travis-ci.org/michaeldegroot/cipher-chain.png?branch=master)](https://travis-ci.org/michaeldegroot/cipher-chain)
[![Coverage Status](https://coveralls.io/repos/github/michaeldegroot/cipher-chain/badge.svg?branch=master)](https://coveralls.io/github/michaeldegroot/cipher-chain?branch=master)
[![Licensing](https://img.shields.io/github/license/michaeldegroot/cipher-chain.svg)](https://raw.githubusercontent.com/michaeldegroot/cipher-chain/master/LICENSE)
[![Repo size](https://img.shields.io/github/repo-size/michaeldegroot/cipher-chain.svg)](https://github.com/michaeldegroot/cipher-chain)
[![Downloads per week](https://img.shields.io/npm/dw/cipher-chain.svg)](https://www.npmjs.com/package/cipher-chain)
[![Node version](https://img.shields.io/node/v/cipher-chain.svg)](https://www.npmjs.com/package/cipher-chain)
[![Help us and star this project](https://img.shields.io/github/stars/michaeldegroot/cipher-chain.svg?style=social)](https://github.com/michaeldegroot/cipher-chain)

Encrypting and decrypting your data in chains made easy!<br>
`cipher-chain` use nodejs her own `crypto` library to ensure security and stability across the board

## Installation

```bash
npm install cipher-chain --save
```

## Usage

```js
const Cipher = require('cipher-chain')

// First create the object with a chosen secret
const cipherChain = new Cipher('uber secret') /// this will use default options settings
// Or
const cipherChain = new cipherChain({
  secret: 'uber secret',
  kdf: 'argon2', // or pbkdf2
  options: { // options for the kdf function, in this case argon2
	  timeCost: 6,
	  memoryCost: 1024 * 4,
	  parallelism: 1,
  }

// You can choose to encrypt and decrypt with just one cipher
let encrypted = await cipherChain.encrypt('secret data', 'aes-256-gcm')
let decrypted = await cipherChain.decrypt(encrypted) // returns: secret data

// You can also encrypt objects/arrays instead of strings
encrypted = await cipherChain.encrypt({ secretdata: true }, 'aes-256-gcm')
decrypted = await cipherChain.decrypt(encrypted) // returns: { secretdata: true }

// Or chain encrypt/decrypt, here doing a three-pass encryption starting from aes-256-gcm to aes-128-ctr and lastly to bf-cbc
encrypted = await cipherChain.encrypt('secret data', ['aes-256-gcm', 'aes-128-ctr', 'bf-cbc'])
decrypted = await cipherChain.decrypt(encrypted) // returns: secret data
```

## Api

#### cipherChain.ciphers()

_Gets a list of all availible ciphers to work with_

#### cipherChain.encrypt(data:[any], encryptionChain:[array, string])

_Encrypts a plaintext string, object, number or array to a cipher-chain encrypted string_

**example:**

```js
let encrypted = await cipherChain.encrypt('secret data', 'aes-256-gcm')
let chainEncrypted = await cipherChain.encrypt('secret data', ['aes-256-gcm', 'bf-cbc', 'camellia-256-cbc'])
```

#### cipherChain.decrypt(encrypted:string)

_Decrypts a given cipher-chain string, will try to return as a object if it can be one_

**example:**

```js
let decrypted = await cipherChain.decrypt(encrypted)
```

## License

Copyright (c) 2019 by [GiveMeAllYourCats](https://github.com/michaeldegroot). Some rights reserved.<br>
[cipher-chain](https://github.com/michaeldegroot/cipher-chain) is licensed under the MIT License as stated in the [LICENSE file](https://github.com/michaeldegroot/cipher-chain/blob/master/LICENSE).
