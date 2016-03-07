import jwt from 'jsonwebtoken'

export default class Tokens {
  constructor (opts) {
    this.publicKey = opts.publicKey.toString()
    this.privateKey = opts.privateKey.toString()
    this.expiresIn = opts.expiresIn || '30d'
  }

  encode (email) {
    var payload = {email: email}
    var token = jwt.sign(payload, this.privateKey, {
      algorithm: 'RS256', expiresIn: this.expiresIn
    })
    return token
  }

  decode (token, cb) {
    jwt.verify(token, this.publicKey, {algorithms: ['RS256']}, cb)
  }

  decodeAsync (token) {
    return new Promise((resolve, reject) => {
      this.decode(token, (err, res) => {
        if (err) return reject(err)
        resolve(res)
      })
    })
  }
}

