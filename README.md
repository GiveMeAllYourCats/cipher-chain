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

Symmetric encryption and decryption of string(s) or file(s) protected via a `secret` string or `secretFile`

## Installation

```bash
npm install cipher-chain --save
```

## How it works

#### - Encrypting

When creating a `cipher-chain` instance you are presented with some options, you can use a `secret` or use a `secretFile`, a `secretFile` is a computer generated 'key' if you will that is a unique signature representing your `secret`

Secondly you will need to define a `chain`, this will be the path the encryption/decryption process goes through to get the encrypted and plaintext respectively. `chain`is a array with string representing all cipher algorithms. The cipher algorithm list can be viewed by calling `cipherchain.ciphers`

When you create a `cipher-chain` instance the script goes through the `chain` list and for every algorithm it creates a kdf generated hashed key derived from the `secret` that matches the `key` length requirements for that particular cipher

Then when you call the `cipherchain.encrypt`, `cipherchain.encryptFile(file)` or `cipherchain.encryptDirectory(directory)` function it checks what the `chain` is and will convert your `plaintext` to `ciphertext` via traversal of the `chain` list.

So if you have a `chain` value of `['aes-256-gcm', 'aes-192-gcm', 'camellia-256-cbc']`

then the encryption process will be:

_plaintext -> aes-256-gcm -> aes-192-gcm -> camellia-256-cbc -> ciphertext_

and decryption process will be:

_ciphertext -> camellia-256-cbc -> aes-192-gcm -> aes-256-gcm -> plaintext_

After encryption chain end a `hmac` is computed of the end resulting `ciphertext` and before decryption chain start the hmac is compared (timings safe) against the end resulting `ciphertext` of that decryption process. If it not verifies a error is thrown

For each algorithm encryption `chain` pass a random `initialization vector` is generated

#### - Decrypting

All encrypted strings have the same format and recgonisable by the starting prefix of `@CC3-` indicating its a cipher-chain encrypted string and its major version 3, so if there are breaking changes because of a major version update in the module, the encrypted ciphertext wont be compatible to decrypt. They can look like this:

`@CC3-72887cf9ecf196d8b13bb05a6141a34c73af7ca719abf994d170ca2cc6629e169d743ef6c93c486079f60 d8cbdf1b7787eee937fe9c4cf62522d0d4d8c304195:0:1:0:ab561e52d1e9c68d3d63c62952c0314f3c73ff01 99657849ef20708af21a291e:3522e975157c2dc1:cbb83e90afeb9a3de67638502148c40b`

If you look closely you can see `:` being delimiters which will have the following result when split:

first the `@CC3-` is removed internally when decrypting the string

```js
;[
	'72887cf9ecf196d8b13bb05a6141a34c73af7ca719abf994d170ca2cc6629e169d743ef6c93c486079f60d8cbdf1b7787eee937fe9c4cf62522d0d4d8c304195',
	'0',
	'1',
	'0',
	'ab561e52d1e9c68d3d63c62952c0314f3c73ff0199657849ef20708af21a291e',
	'3522e975157c2dc1',
	'cbb83e90afeb9a3de67638502148c40b'
]
```

The mapping for this format is as followed:

`@CC[majorVersioNumberCipherChain]-[hmac]:[cipherAlgorithmId]:[autoPadding]:[authTag]:[kdfSalt]:[initializationVector]:[encryptedData]`

So we can conclude we have the following data when decrypting the string:

```js
const data = {
	hmac: '72887cf9ecf196d8b13bb05a6141a34c73af7ca719abf994d170ca2cc6629e169d743ef6c93c486079f60d8cbdf1b7787eee937fe9c4cf62522d0d4d8c304195',
	cipherAlgorithmId: '0',
	autoPadding: '1',
	authTag: '0',
	kdfSalt: 'ab561e52d1e9c68d3d63c62952c0314f3c73ff0199657849ef20708af21a291e',
	initializationVector: '3522e975157c2dc1',
	encryptedData: 'cbb83e90afeb9a3de67638502148c40b'
}
```

Cipher-chain knows this internally when trying to decrypt your strings. The only piece of the puzzle here to decrypt the `encryptedData` variable is if we know the `secret`

## Initialization

```js
const CipherChain = require('cipher-chain')

const aAsyncFunction = async () => {
	const options = {} // default options
	const cipherchain = await new CipherChain(options)
}
```

## Options

- `secret` The secret to use for key stretching and encrypting/decrypting all algorithms with. No default, must be specified unless `secretFile` used.
- `secretFile` A path to a file that points to a cipher-chain generate key file (256 bytes) used for encryption/decryption. If the file does not exist, it is generated, saved and used as the `secret`. If the file is found the contents are loaded as the `secret`
- `hmacVerify` Do `encrypt-then-MAC` to verify authenticity of the encrypted ciphertext
- `autoPadding` boolean to switch auto padding for the cipher
- `concurrentFiles` how many concurrent files will be encrypted and decrypted at any given time. Default 100
- `hmacAlgorithm` string for what algorith the hmac verify should use. Default `sha512`
- `kdf` object setting for kdf, **see below**

**kdf object setting for the kdf option**

```js
const argon2 = require('argon2')
{
    use: 'argon2', // or blake2, scrypt, pbkdf2,
    saltLength: 4, // salt length for the kdf, bigger value means bigger ciphertext data, especially with multiple chain encrypts
    options: {
      argon2: { // some argon2 setings you could do
        type: argon2.argon2i,
        memoryCost: 1024 * 4, // 4mb
        timeCost: 4
      },
      pbkdf2: { // some pbkdf2 setings you could do
        rounds: 10000,
        hash: 'sha512'
      }
    }
}
```

## Methods

#### cipherchain.ciphers

_Gets a list of all available ciphers to work with_

#### cipherchain.kdfs

_Gets a list of all available KDFs to work with_

#### cipherchain.encrypt(plaintext:[string])

_Encrypts a plaintext to a ciphertext_

```js
let encrypted = await cipherchain.encrypt('secret data')
```

#### cipherchain.decrypt(ciphertext:[string])

_Decrypts a ciphertext to a plaintext_

```js
let decrypted = await cipherchain.decrypt(encrypted)
```

#### cipherchain.encryptFile(filename:[path])

_Encrypts a file, also hashes filename_

```js
await cipherchain.encryptFile(path.join('../', 'encryptme.txt'))
```

#### cipherchain.decryptFile(filename:[path])

_Decrypts a file_

```js
await cipherchain.decryptFile(path.join('../', 'encryptme.txt'))
```

#### cipherchain.encryptDirectory(directory:[path])

_Encrypts a directory, also hashes filenames_

```js
await cipherchain.encryptDirectory(path.join('../', 'encryptme'))
```

#### cipherchain.decryptDirectory(directory:[path])

_Decrypts a directory_

```js
await cipherchain.decryptDirectory(path.join('../', 'encryptme'))
```

## Example

```js
const CipherChain = require('cipher-chain')

const start = async () => {
	const cipherchain = await new CipherChain({
		secret: 'very secret!',
		kdf: 'argon2',
		chain: ['aes-256-gcm', 'blowfish', 'camellia-256-cbc'],
		options: {
			argon2: {
				timeCost: 6,
				memoryCost: 1024 * 4,
				parallelism: 1
			}
		}
	})

	const ciphers = cipherchain.ciphers // List of cipher algorithms to use in your chain
	const kdfs = cipherchain.kdfs // List of KDFs (key derivation function) to use

	// Encrypt/decrypt a string
	const ciphertext = await cipherchain.encrypt('encrypt this')
	const plaintext = await cipherchain.decrypt(ciphertext)

	// Encrypt/decrypt a file
	await cipherchain.encryptFile('./file.txt')
	await cipherchain.decryptFile('./file.txt')

	// Encrypt/decrypt a directory
	await cipherchain.encryptDirectory('./directory')
	await cipherchain.decryptDirectory('./directory')
}

start()
```

## License

Copyright (c) 2020 by [GiveMeAllYourCats](https://github.com/michaeldegroot). Some rights reserved.<br>
[cipher-chain](https://github.com/michaeldegroot/cipher-chain) is licensed under the MIT License as stated in the [LICENSE file](https://github.com/michaeldegroot/cipher-chain/blob/master/LICENSE).
