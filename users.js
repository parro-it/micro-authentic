import crypto from 'crypto'

let db = {}

export default class Users {
  reset () {
    db = {}
  }

  createUserAsync (email, password) {
    return new Promise((resolve, reject) =>
      this.createUser(email, password, (err, res) => {
        if (err) return reject(err)
        resolve(res)
      })
    )
  }

  createUser (email, password, cb) {
    if (!validEmail(email)) return cb(new Error('Invalid Email'))
    if (!validPassword(password)) return cb(new Error('Invalid Password'))

    this.findUser(email, function (err, user) {
      if (!err && user) return cb(new Error('User Exists'))

      generateToken(30, function (err, token) {
        if (err) return cb(err)

        var data = {
          emailConfirmed: false,
          confirmToken: token
        }

        const createdDate = new Date().toISOString()
        const user2 =
          db[email] =
            { password, email, data, createdDate }

        cb(null, user2)
      })
    })
  }

  confirmUserAsync (email, token) {
    return new Promise((resolve, reject) =>
      this.confirmUser(email, token, (err, res) => {
        if (err) return reject(err)
        resolve(res)
      })
    )
  }

  confirmUser (email, token, cb) {
    this.findUser(email, function (err, user) {
      if (err) return cb(err)

      if (user.data.emailConfirmed === true) return cb(new Error('Already Confirmed'))
      if (user.data.confirmToken !== token) return cb(new Error('Token Mismatch'))

      user.data.emailConfirmed = true
      user.data.confirmToken = undefined

      db[email] = user
      cb(null, user)
    })
  }

  changePasswordAsync (email, password) {
    return new Promise((resolve, reject) =>
      this.changePassword(email, password, (err, res) => {
        if (err) return reject(err)
        resolve(res)
      })
    )
  }

  changePassword (email, password, token, cb) {
    if (!token) return cb(new Error('Invalid Token'))
    if (!validPassword(password)) return cb(new Error('Invalid Password'))

    this.findUser(email, function (err, user) {
      if (err) return cb(err)
      if (!user.data.changeToken) return cb(new Error('Token Expired'))

      if (user.data.changeToken !== token) return cb(new Error('Token Mismatch'))

      if (!(user.data.changeExpires > Date.now())) {
        return cb(new Error('Token Expired'))
      }

      user.data.changeToken = undefined
      user.data.changeExpires = undefined
      user.data.emailConfirmed = true
      user.password = password

      cb(null, user)
    })
  }

  createChangeTokenAsync (email, expires) {
    return new Promise((resolve, reject) =>
      this.createChangeToken(email, expires, (err, res) => {
        if (err) return reject(err)
        resolve(res)
      })
    )
  }

  createChangeToken (email, expires = Date.now() + 2 * 24 * 3600 * 1000, cb) {
    var self = this

    this.findUser(email, function (err, user) {
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

    generateToken(16, function (err, pw) {
      if (err) return cb(err)
      self.createUser(email, pw, function (err, user) {
        if (err) return cb(err)

        self.confirmUser(email, user.data.confirmToken, function (err) {
          if (err) return cb(err)

          self.createChangeToken(email, expires, cb)
        })
      })
    })
  }

  findUserAsync (email) {
    return new Promise((resolve, reject) =>
      this.findUser(email, (err, res) => {
        if (err) return reject(err)
        resolve(res)
      })
    )
  }

  findUser (email, cb) {
    email = email || ''

    if (email in db) {
      return cb(null, db[email])
    }

    cb(new Error('User Not Found'))
  }

  checkPasswordAsync (email, pass) {
    return new Promise((resolve, reject) =>
      this.checkPassword(email, pass, (err, res) => {
        if (err) return reject(err)
        resolve(res)
      })
    )
  }

  checkPassword (email, pass, cb) {
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

  crypto.randomBytes(len, function (ex, buf) {
    cb(null, buf.toString(encoding))
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

