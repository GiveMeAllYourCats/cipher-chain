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

Symmetric encryption and decryption in cipher chains protected by a unique `secret` strings per chain, Can compress data (zlib), Can encrypt/decrypt files and whole directories. Uses [zxcvbn](https://github.com/dropbox/zxcvbn) for `secret` requirements with minimum of 24 characters per secret. encrypt-then-mac authentication.

## Installation

```bash
npm install cipher-chain --save
```

## How it works

#### - Encrypting

When creating a `cipher-chain` instance you are presented with some options, First you need to define a `secret` this is a array and it needs to have the same length as your `chain` variable. Secrets need to be unique from each other, error will be thrown if not. If `enableSecurityRequirements` is enabled (default true) then secret(s) need to be min 24 chars and comply to at least a score of 3 from the [zxcvbn](https://github.com/dropbox/zxcvbn) package.

So secondly you will need to define a `chain`, this will be the path the encryption/decryption process goes through to get the encrypted and plaintext respectively. `chain` is a array with strings representing all cipher algorithms names. The cipher algorithm list can be viewed by calling `cipherchain.ciphers`

When you create a `cipher-chain` instance the script goes through the `chain` list and for every algorithm it creates a KDF generated hashed key derived from the `secret` array corresponding index of the current chain index which is used as the key for that specific encipherment algorithm in the chain.

Then when you call the `cipherchain.encrypt`, `cipherchain.encryptFile(file)` or `cipherchain.encryptDirectory(directory)` function it checks what the `chain` is and will convert your `plaintext` to `ciphertext` via traversal of the `chain` list.

So if you have a `chain` value of `['aes-256-gcm', 'aes-192-gcm', 'camellia-256-cbc']`

then the encryption process will be:

_plaintext -> aes-256-gcm -> aes-192-gcm -> camellia-256-cbc -> ciphertext_

and decryption process will be:

_ciphertext -> camellia-256-cbc -> aes-192-gcm -> aes-256-gcm -> plaintext_

After encryption chain end a `hmac` is computed of the end resulting `ciphertext` and before decryption chain start the hmac is compared (timings safe) against the end resulting `ciphertext` of that decryption process. If it not verifies a error is thrown

For each algorithm encryption `chain` pass a random `initialization vector` is generated

#### - Decrypting

All encrypted strings have the same format and recgonisable by the starting prefix of `@CC4-` indicating its a cipher-chain encrypted string and its major version 3, so if there are breaking changes because of a major version update in the module, the encrypted ciphertext wont be compatible to decrypt. They can look like this:

`@CC4-56832c1b9e806bc1164523ba86925707a3ba6eb59716ae3c148426a036967f9469bb73a7cdd038969b6172098465ea33e97de072ba112112cf46f00ecf31dd40:80c0b153a3f83b34b481c3e5843c2c9c:038bb16ebbd0bdcecec2d82b:53b04561ea178266f146b52f7dd1e07386f5c95bf1efad75f06bbbbc702ea0b8:0ed43ae8`

or if `compressData` option is set to true:

`eJwVj8dtBEAMAysysAqrcC8DV4li/yV4/SRIgsPf75d/FGskqtMw9jJyWxMfVgftdYNwttmUubAjWrygCVAcVZan8hnlnDcpQwwGq+9KX2BEvngkKSCX0aKllmFMKu4ltSr94MUocIQZclvfID8v7nryeOYHICKu1lzr8RBCnOalj+aDnHMYyF/eGtfx/8k+dQKLpPF0A9PKg8cAffabdXqV+CDVFdf+Az+9SUQ=`

If you look closely you can see `:` being delimiters which will have the following result when split:

first the `@CC4-` is removed internally when decrypting the string

```js
;[
	'56832c1b9e806bc1164523ba86925707a3ba6eb59716ae3c148426a036967f9469bb73a7cdd038969b6172098465ea33e97de072ba112112cf46f00ecf31dd40',
	'80c0b153a3f83b34b481c3e5843c2c9c',
	'038bb16ebbd0bdcecec2d82b',
	'53b04561ea178266f146b52f7dd1e07386f5c95bf1efad75f06bbbbc702ea0b8',
	'0ed43ae8'
]
```

The mapping for this format is as followed:

`@CC[majorVersionNumberCipherChain]-[hmac]:[authTag]:[kdfSalt]:[initializationVector]:[encryptedData]`

So we can conclude we have the following data when decrypting the string:

```js
const data = {
	hmac: '56832c1b9e806bc1164523ba86925707a3ba6eb59716ae3c148426a036967f9469bb73a7cdd038969b6172098465ea33e97de072ba112112cf46f00ecf31dd40',
	authTag: '80c0b153a3f83b34b481c3e5843c2c9c',
	kdfSalt: '038bb16ebbd0bdcecec2d82b',
	initializationVector: '53b04561ea178266f146b52f7dd1e07386f5c95bf1efad75f06bbbbc702ea0b8',
	encryptedData: '0ed43ae8'
}
```

Cipher-chain knows internally which algorithm cipher to use for this to decrypt your strings. The only piece of the puzzle here to decrypt the `encryptedData` variable is if we know the `secret` kdf hash for that specific chain

## Initialization

```js
const CipherChain = require('cipher-chain')

const aAsyncFunction = async () => {
	const options = {} // default options
	const cipherchain = await new CipherChain(options)
}
```

## Options

| Argument                     | Explanation                                                                                                                                                              | Default     |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------- |
| `secret`                     | The secret(s) to use for specific chains, needs to be a array and as long as your `chain` option                                                                         | `undefined` |
| `chain`                      | Array with strings that hold the cipher algorithms you want to use as a path to traverse from plain to cipher and vice versa                                             | `undefined` |
| `autoPadding`                | Boolean to switch auto padding for the cipher.                                                                                                                           | `true`      |
| `timingSafeCheck`            | Boolean for function equal check for hmac based on a constant-time algorithm without leaking timing information that would allow an attacker to guess one of the values. | `true`      |
| `compressData`               | Boolean to compress end result after encryption to save data space, works for all encrypt functions                                                                      | `true`      |
| `concurrentFiles`            | How many concurrent files will be encrypted and decrypted at any given time.                                                                                             | `20`        |
| `enableSecurityRequirements` | Enables the [zxcvbn](https://github.com/dropbox/zxcvbn) package and min 24 char secret(s) requirements for extra security.                                               | `true`      |
| `hmacAlgorithm`              | String for what algorith the hmac verify should use.                                                                                                                     | `sha512`    |
| `kdf`                        | See Below                                                                                                                                                                | See Below   |

```js
 // const argon2 = require('argon2')
{
    use: 'argon2', // or blake2, scrypt, pbkdf2,
    saltLength: 12, // salt length for the kdf, bigger value means bigger ciphertext data, especially with multiple chain encrypts
    options: {
      argon2: { // some argon2 setings you could do
        type: argon2.argon2i,
        memoryCost: 1024 * 8,
        timeCost: 6
      },
      pbkdf2: { // some pbkdf2 setings you could do, since 'use' in options is set to 'argon2' this is obsolete
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
const newFilename = await cipherchain.encryptFile(path.join('../', 'encryptme.txt'))
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
		secret: ['BxDPiKEAEaHZPiKERqLZDVaz', 'WRWqLZDPiKEqLZDsEFMCmgqLZDHH', 'IeiKEBxDRwvFmYERqLZjOi'],
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
	const newFilename = await cipherchain.encryptFile('./file.txt')
	await cipherchain.decryptFile(newFilename)

	// Encrypt/decrypt a directory
	await cipherchain.encryptDirectory('./directory')
	await cipherchain.decryptDirectory('./directory')
}

start()
```

## License

Copyright (c) 2020 by [GiveMeAllYourCats](https://github.com/michaeldegroot). Some rights reserved.<br>
[cipher-chain](https://github.com/michaeldegroot/cipher-chain) is licensed under the MIT License as stated in the [LICENSE file](https://github.com/michaeldegroot/cipher-chain/blob/master/LICENSE).
