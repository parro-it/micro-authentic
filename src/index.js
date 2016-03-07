import API from './api'
import { parse } from 'url'
import error from './error'

function logMail (email) {
  process.stdout.write(JSON.stringify(email) + '\n')
}

function methodNotAllowed () {
  error(405, 'Method not allowed')
}

function isNotPost (req) {
  return req.method.toUpperCase() !== 'POST'
}

function isNotGet (req) {
  return req.method.toUpperCase() !== 'GET'
}

export function withOptions ({
  publicKey,
  privateKey,
  sendEmail = logMail
} = {}) {
  const api = new API({publicKey, privateKey, sendEmail})

  return async function routeReq (req, res) {
    switch (parse(req.url).pathname) {
      case '/login':
        if (isNotPost(req)) methodNotAllowed()
        return await api.login(req, res)
      case '/signup':
        if (isNotPost(req)) methodNotAllowed()
        return await api.signup(req, res)
      case '/confirm':
        if (isNotPost(req)) methodNotAllowed()
        return await api.confirm(req, res)
      case '/change-password-request':
        if (isNotPost(req)) methodNotAllowed()
        return await api.changePasswordRequest(req, res)
      case '/change-password':
        if (isNotPost(req)) methodNotAllowed()
        return await api.changePassword(req, res)
      case '/public-key':
        if (isNotGet(req)) methodNotAllowed()
        return await api.publicKey(req, res)
      default:
        error(404, 'Resource not found')
    }
  }
}

