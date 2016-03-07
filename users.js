import crypto from 'crypto'

let db = {}

export default class Users {
  reset () {
    db = {}
  }

  async createUserAsync (email, password) {
    if (!validEmail(email)) throw new Error('Invalid Email')
    if (!validPassword(password)) throw new Error('Invalid Password')

    let user
    try {
      user = await this.findUserAsync(email)
    } catch (err) {
      // ignore
    }
    if (user) throw new Error('User Exists')

    const token = await generateToken(30)

    var data = {
      emailConfirmed: false,
      confirmToken: token
    }

    const createdDate = new Date().toISOString()
    const newUser = db[email] = { password, email, data, createdDate }
    return newUser
  }

  async confirmUserAsync (email, token) {
    const user = await this.findUserAsync(email)

    if (user.data.emailConfirmed === true) throw new Error('Already Confirmed')
    if (user.data.confirmToken !== token) throw new Error('Token Mismatch')

    user.data.emailConfirmed = true
    user.data.confirmToken = undefined

    db[email] = user

    return user
  }

  async changePasswordAsync (email, password, token) {
    if (!token) throw new Error('Invalid Token')
    if (!validPassword(password)) throw new Error('Invalid Password')

    const user = await this.findUserAsync(email)

    if (!user.data.changeToken) throw new Error('Token Expired')
    if (user.data.changeToken !== token) throw new Error('Token Mismatch')
    if (!(user.data.changeExpires > Date.now())) throw new Error('Token Expired')

    user.data.changeToken = undefined
    user.data.changeExpires = undefined
    user.data.emailConfirmed = true
    user.password = password

    return user
  }

  createChangeTokenAsync (email, expires) {
    return new Promise((resolve, reject) =>
      this._createChangeToken(email, expires, (err, res) => {
        if (err) return reject(err)
        resolve(res)
      })
    )
  }

  _createChangeToken (email, expires = Date.now() + 2 * 24 * 3600 * 1000, cb) {
    var self = this

    this._findUser(email, function (err, user) {
      if (err) {
        if (err.message === 'User Not Found') {
          // Create user and try again
          return self.createWithPasswordChange(email, expires, cb)
        }
        return cb(err)
      }

      generateToken(30, function (err, token) {
        if (err) return cb(err)
        if (user.data == null) user.data = {}

        user.data.changeToken = token
        user.data.changeExpires = expires

        db[email] = user
        cb(null, user)
      })
    })
  }

  createWithPasswordChange (email, expires, cb) {
    var self = this

    if (typeof expires === 'function') {
      cb = expires
      expires = Date.now() + 90 * 24 * 3600 * 1000
    }

    generateToken(16, async function (err, pw) {
      if (err) return cb(err)
      try {
        const user = await self.createUserAsync(email, pw)
        await self.confirmUserAsync(email, user.data.confirmToken)
        self._createChangeToken(email, expires, cb)
      } catch (err) {
        cb(err)
      }
    })
  }

  findUserAsync (email) {
    return new Promise((resolve, reject) =>
      this._findUser(email, (err, res) => {
        if (err) return reject(err)
        resolve(res)
      })
    )
  }

  _findUser (email, cb) {
    email = email || ''

    if (email in db) {
      return cb(null, db[email])
    }

    cb(new Error('User Not Found'))
  }

  checkPasswordAsync (email, pass) {
    return new Promise((resolve, reject) =>
      this._checkPassword(email, pass, (err, res) => {
        if (err) return reject(err)
        resolve(res)
      })
    )
  }

  _checkPassword (email, pass, cb) {
    email = email || ''
    pass = pass || ''

    if (email in db) {
      const user = db[email]
      if (user.password === pass) {
        return cb(null, user)
      }
      return cb(new Error('Password Mismatch'))
    }

    return cb(new Error('User Not Found'))
  }
}

function generateToken (len, encoding, cb) {
  len = len || 1
  if (typeof encoding === 'function') {
    cb = encoding
    encoding = 'hex'
  }
  encoding = encoding || 'hex'

  return new Promise((resolve, reject) => {
    crypto.randomBytes(len, function (ex, buf) {
      const tk = buf.toString(encoding)
      if (cb) {
        cb(null, tk)
      } else {
        resolve(tk)
      }
    })
  })
}

function validEmail (email) {
  email = email || ''
  return /^[^@]+@[^@]+\.\w{2,}$/.test(email)
}

function validPassword (password) {
  password = password || ''
  return password.length >= 6
}

