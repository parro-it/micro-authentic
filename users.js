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

  async createChangeTokenAsync (email, expires = Date.now() + 90 * 24 * 3600 * 1000) {
    var self = this

    try {
      const user = await this.findUserAsync(email)
      const token = await generateToken(30)
      if (user.data == null) user.data = {}

      user.data.changeToken = token
      user.data.changeExpires = expires

      db[email] = user

      return user
    } catch (err) {
      if (err.message === 'User Not Found') {
        // Create user and try again
        return await self.createWithPasswordChange(email, expires)
      }
      throw err
    }
  }

  async createWithPasswordChange (email, expires) {
    var self = this

    const pw = await generateToken(16)
    const user = await self.createUserAsync(email, pw)
    await self.confirmUserAsync(email, user.data.confirmToken)
    await self.createChangeTokenAsync(email, expires)
    return user
  }

  async findUserAsync (email = '') {
    if (email in db) {
      return Promise.resolve(db[email])
    }

    return Promise.reject(new Error('User Not Found'))
  }

  async checkPasswordAsync (email, pass) {
    email = email || ''
    pass = pass || ''

    if (email in db) {
      const user = db[email]
      if (user.password === pass) {
        return Promise.resolve(user)
      }
      return Promise.reject(new Error('Password Mismatch'))
    }

    return Promise.reject(new Error('User Not Found'))
  }
}

function generateToken (len = 1, encoding = 'hex') {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(len, function (ex, buf) {
      const tk = buf.toString(encoding)
      resolve(tk)
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

