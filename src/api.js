import URL from 'url'
import Tokens from './tokens'
import Users from './users'

import { send, json } from 'micro'

export default class API {
  constructor (opts) {
    this.sendEmail = opts.sendEmail
    this.tokens = new Tokens(opts)
    this.Users = new Users(opts.db)
  }

  async publicKey (req, res) {
    send(res, 200, {
      success: true,
      data: {
        publicKey: this.tokens.publicKey
      }
    })
  }

  async signup (req, res) {
    var self = this

    const userData = await json(req)
    var email = userData.email
    var pass = userData.password
    var confirmUrl = userData.confirmUrl

    const user = await self.Users.createUserAsync(email, pass)

    if (confirmUrl) {
      var urlObj = URL.parse(confirmUrl, true)
      urlObj.query.confirmToken = user.data.confirmToken
      urlObj.query.email = email
      confirmUrl = URL.format(urlObj)
    }

    var emailOpts = {}
    Object.keys(userData).forEach(function (k) {
      if (k !== 'password') emailOpts[k] = userData[k]
    })

    emailOpts.type = 'signup'
    emailOpts.email = email
    emailOpts.confirmUrl = confirmUrl
    emailOpts.confirmToken = user.data.confirmToken

    await self.sendEmail(emailOpts)

    send(res, 201, {
      success: true,
      message: 'User created. Check email for confirmation link.',
      data: {
        email: user.email,
        createdDate: user.createdDate
      }
    })
  }

  async confirm (req, res) {
    var self = this

    const userData = await json(req)

    var email = userData.email
    var confirmToken = userData.confirmToken
    await self.Users.confirmUserAsync(email, confirmToken)

    var token = self.tokens.encode(email)
    send(res, 202, {
      success: true,
      message: 'User confirmed.',
      data: {
        authToken: token
      }
    })
  }

  async login (req, res) {
    var self = this

    const userData = await json(req)
    var email = userData.email
    var pass = userData.password

    const user = await self.Users.checkPasswordAsync(email, pass)

    var isConfirmed = (user.data || {}).emailConfirmed
    if (!isConfirmed) {
      const err = new Error('User Not Confirmed')
      err.statusCode = 401
      throw err
    }

    var token = self.tokens.encode(email)
    send(res, 202, {
      success: true,
      message: 'Login successful.',
      data: {
        authToken: token
      }
    })
  }

  async changePasswordRequest (req, res) {
    var self = this

    const userData = await json(req)
    var email = userData.email
    var changeUrl = userData.changeUrl

    const changeToken = await self.Users.createChangeTokenAsync(email)

    if (changeUrl) {
      var urlObj = URL.parse(changeUrl, true)
      urlObj.query.changeToken = changeToken
      urlObj.query.email = email
      changeUrl = URL.format(urlObj)
    }

    var emailOpts = {}
    Object.keys(userData).forEach(function (k) {
      emailOpts[k] = userData[k]
    })

    emailOpts.type = 'change-password-request'
    emailOpts.email = email
    emailOpts.changeUrl = changeUrl
    emailOpts.changeToken = changeToken

    await self.sendEmail(emailOpts)

    send(res, 200, {
      success: true,
      message: 'Change password request received. Check email for confirmation link.'
    })
  }

  async changePassword (req, res) {
    var self = this

    const userData = await json(req)

    var email = userData.email
    var password = userData.password
    var changeToken = userData.changeToken

    await self.Users.changePasswordAsync(email, password, changeToken)
    await self.Users.checkPasswordAsync(email, password)

    var authToken = self.tokens.encode(email)

    send(res, 200, {
      success: true,
      message: 'Password changed.',
      data: {
        authToken: authToken
      }
    })
  }
}

