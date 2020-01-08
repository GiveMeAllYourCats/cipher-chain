const assert = require('assert')
const fs = require('fs')
const path = require('path')
const cipherChain = require('../../cipher-chain')
const _ = require('lodash')

describe('cipherchain stuff', function() {
  before(done => {
    setTimeout(() => {
      done()
    }, 500)
  })
  after(done => {
    setTimeout(() => {
      done()
    }, 500)
  })

  it('Yeets', done => {
    console.log('YEeet!')
    done()
  })
})
