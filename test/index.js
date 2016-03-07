import 'babel-register'
import fs from 'fs'
import test from 'ava'
import {withOptions as Authentic} from '../src'
import UsersClass from '../src/users'
import Tokens from '../src/tokens'
import { join } from 'path'
import listen from './_listen'
import fetch from 'node-fetch'

const Users = new UsersClass()
const publicKey = fs.readFileSync(join(__dirname, 'fixtures/rsa-public.pem'))
const privateKey = fs.readFileSync(join(__dirname, 'fixtures/rsa-private.pem'))

const tokens = new Tokens({
  publicKey: publicKey,
  privateKey: privateKey
})

let lastEmail

async function post (url, data) {
  const auth = Authentic({
    publicKey: publicKey,
    privateKey: privateKey,
    sendEmail: async function (email) {
      lastEmail = email
    }
  })

  const base = await listen(auth)

  return await fetch(base + url, {
    method: 'POST',
    body: JSON.stringify(data),
    headers: {'Content-Type': 'application/json'}
  })
}

async function get (url) {
  const auth = Authentic({
    publicKey: publicKey,
    privateKey: privateKey,
    sendEmail: async function (email) {
      lastEmail = email
    }
  })

  const base = await listen(auth)

  return await fetch(base + url)
}

test('Auth: should get public-key', async (t) => {
  const res = await get('/public-key')
  const data = await res.json()
  t.is(data.success, true, 'should succeed')
  t.is(data.data.publicKey.length, 800, 'should have publicKey')
})

test('Auth: Signup: should be able to sign up', async (t) => {
  var postData = {
    email: 'david@scalehaus.io',
    password: 'swordfish',
    confirmUrl: 'http://example.com/confirm'
  }

  const res = await post('/signup', postData)
  t.is(res.status, 201)

  var data = await res.json()
  t.is(data.success, true, 'should succeed')
  t.is(data.message, 'User created. Check email for confirmation link.', 'should have message')
  t.is(data.data.email, 'david@scalehaus.io', 'should have email')
  t.is(data.data.createdDate.length, 24, 'should have createdDate')
})

test('Auth: Login: should fail without confirm', async (t) => {
  Users.reset()
  var postData = {
    email: '123david@scalehaus.io', password: 'swordfish'
  }

  await Users.createUserAsync(
    '123david@scalehaus.io',
    'swordfish'
  )

  const res = await post('/login', postData)
  t.is(res.status, 401)

  var data = await res.json()
  t.is(data.success, false, 'should not succeed')
  t.is(data.error, 'User Not Confirmed', 'should have error')
})

test('Auth: Signup: sendEmail should get email options', async (t) => {
  var postData = {
    email: 'email@scalehaus.io',
    password: 'swordfish',
    confirmUrl: 'http://example.com/confirm',
    from: 'from@somewhere.com',
    subject: 'Client Defined Subject',
    html: '<h1>Welcome</h1><p><a href="{{confirmUrl}}">Confirm</a></p>'
  }

  const res = await post('/signup', postData)
  t.is(res.status, 201)

  t.notOk(lastEmail.password, 'should not have password')
  t.is(lastEmail.from, postData.from, 'should have from')
  t.is(lastEmail.subject, postData.subject, 'should have subject')
  t.is(lastEmail.html, postData.html, 'should have html')
})

test('Auth: Signup: should error for existing user', async (t) => {
  Users.reset()

  await Users.createUserAsync(
    'david@scalehaus.io',
    'swordfish'
  )
  var postData = {
    email: 'david@scalehaus.io',
    password: 'swordfish',
    confirmUrl: 'http://example.com/confirm'
  }

  const res = await post('/signup', postData)

  t.is(res.status, 400)

  var data = await res.json()
  t.not(data.success, true, 'should not succeed')
  t.is(data.error, 'User Exists', 'should have error')
})

test('Auth: Confirm: should error for mismatch', async (t) => {
  var postData = {
    email: 'david@scalehaus.io',
    confirmToken: 'incorrect'
  }

  const res = await post('/confirm', postData)

  t.is(res.status, 401)

  var data = await res.json()
  t.is(data.success, false, 'should not succeed')
  t.is(data.error, 'Token Mismatch')
})

test('Auth: Confirm: should confirm user', async (t) => {
  Users.reset()
  const user = await Users.createUserAsync(
    '333david@scalehaus.io',
    'fdsfdsfdfd'
  )
  var postData = {
    email: '333david@scalehaus.io',
    confirmToken: user.data.confirmToken
  }

  const res = await post('/confirm', postData)

  t.is(res.status, 202)

  var data = await res.json()
  t.is(data.success, true, 'should succeed')
  t.is(data.message, 'User confirmed.', 'should have message')
  const payload = await tokens.decodeAsync(data.data.authToken)
  t.is(payload.email, '333david@scalehaus.io', 'payload should have email')
  t.ok(payload.iat, 'should have iat')
})

test('Auth: Login: should error for unknown user', async (t) => {
  Users.reset()

  var postData = {
    email: 'not--david@scalehaus.io',
    password: 'not swordfish'
  }

  const res = await post('/login', postData)

  t.is(res.status, 401)

  var data = await res.json()
  t.is(data.success, false, 'should not succeed')
  t.is(data.error, 'User Not Found', 'should have error message')
})

test('Auth: Login: should error for wrong pass', async (t) => {
  Users.reset()
  var postData = {
    email: 'david@scalehaus.io',
    password: 'not swordfish'
  }
  const user = await Users.createUserAsync(
    'david@scalehaus.io',
    'swordfish'
  )

  await Users.confirmUserAsync(
    'david@scalehaus.io',
    user.data.confirmToken
  )

  const res = await post('/login', postData)

  t.is(res.status, 401)

  var data = await res.json()
  t.is(data.success, false, 'should not succeed')
  t.is(data.error, 'Password Mismatch', 'should have error message')
})

test('Auth: Login: should login', async (t) => {
  Users.reset()
  const user = await Users.createUserAsync(
    'david@scalehaus.io',
    'swordfish'
  )
  await Users.confirmUserAsync(
    'david@scalehaus.io',
    user.data.confirmToken
  )

  var postData = {
    email: 'david@scalehaus.io',
    password: 'swordfish'
  }

  const res = await post('/login', postData)

  t.is(res.status, 202)

  var data = await res.json()
  t.is(data.success, true, 'should succeed', 'should succeed')
  t.is(data.message, 'Login successful.', 'should have message')

  const payload = await tokens.decodeAsync(data.data.authToken)

  t.is(payload.email, 'david@scalehaus.io', 'payload should have email')
  t.ok(payload.iat, 'should have iat')
  t.ok(payload.exp, 'should have exp')
})

test('Auth: Change Password Request', async (t) => {
  var postData = {
    email: 'david@scalehaus.io',
    changeUrl: 'http://example.com/change'
  }
  Users.reset()

  const user2 = await Users.createUserAsync('david@scalehaus.io', 'dsfdsfdsf345')
  await Users.confirmUserAsync(
    'david@scalehaus.io',
    user2.data.confirmToken
  )

  const res = await post('/change-password-request', postData)

  t.is(res.status, 200)

  var data = await res.json()
  t.ok(data.success, 'should succeed')
  t.is(data.message, 'Change password request received. Check email for confirmation link.')

  const user = await Users.findUserAsync(postData.email)

  t.is(user.data.emailConfirmed, true, 'email should be confirmed')
  t.is(user.data.changeToken.length, 60, 'should have change token')
  t.ok(user.data.changeExpires > Date.now(), 'should have changeExpires')
})

test('Auth: Change Password Request should fix case', async (t) => {
  var postData = {
    email: 'TitleCase24@scalehaus.io',
    changeUrl: 'http://example.com/change'
  }
  Users.reset()

  const user2 = await Users.createUserAsync('titlecase24@scalehaus.io', 'dsfdsfdsf345')
  await Users.confirmUserAsync(
    'titlecase24@scalehaus.io',
    user2.data.confirmToken
  )

  const res = await post('/change-password-request', postData)

  t.is(res.status, 200)

  var data = await res.json()
  t.ok(data.success, 'should succeed')
  t.is(data.message, 'Change password request received. Check email for confirmation link.')

  const user = await Users.findUserAsync(postData.email)

  t.is(user.data.emailConfirmed, true, 'email should be confirmed')
  t.is(user.data.changeToken.length, 60, 'should have change token')
  t.ok(user.data.changeExpires > Date.now(), 'should have changeExpires')
})

test('Auth: Change Password Request: will create confirmed user', async (t) => {
  var postData = {
    email: 'unknownuser@scalehaus.io',
    changeUrl: 'http://example.com/change'
  }

  Users.reset()

  const user2 = await Users.createUserAsync('titlecase24@scalehaus.io', 'dsfdsfdsf345')
  await Users.confirmUserAsync(
    'titlecase24@scalehaus.io',
    user2.data.confirmToken
  )

  const res = await post('/change-password-request', postData)

  t.is(res.status, 200)

  var data = await res.json()
  t.ok(data.success, 'should succeed')
  t.is(data.message, 'Change password request received. Check email for confirmation link.')

  const user = await Users.findUserAsync(postData.email)

  t.is(user.data.emailConfirmed, true, 'email should be confirmed')
  t.is(user.data.changeToken.length, 60, 'should have change token')
  t.ok(user.data.changeExpires > Date.now(), 'should have changeExpires')
})

test('Auth: Change Password Request: sendEmail should get email options', async (t) => {
  var postData = {
    email: 'email@scalehaus.io',
    changeUrl: 'http://example.com/change',
    from: 'from@somewhere.com',
    subject: 'Change PW Subject',
    html: '<h1>Change PW</h1><p><a href="{{changeUrl}}">Change</a></p>'
  }

  Users.reset()

  const user2 = await Users.createUserAsync('email@scalehaus.io', 'dsfdsfdsf345')
  await Users.confirmUserAsync(
    'email@scalehaus.io',
    user2.data.confirmToken
  )

  const res = await post('/change-password-request', postData)

  t.is(res.status, 200)

  var data = await res.json()

  t.ok(data.success, 'should succeed')
  t.is(data.message, 'Change password request received. Check email for confirmation link.')

  t.is(lastEmail.from, postData.from, 'should have from')
  t.is(lastEmail.subject, postData.subject, 'should have subject')
  t.is(lastEmail.html, postData.html, 'should have html')
})

test('Auth: Change Password: should error with wrong token', async (t) => {
  var postData = {
    email: 'david@scalehaus.io',
    changeToken: 'wrong token',
    password: 'newpass'
  }

  Users.reset()

  const user2 = await Users.createUserAsync(
    'david@scalehaus.io',
    'dsfdsfdsf345'
  )

  await Users.confirmUserAsync(
    'david@scalehaus.io',
    user2.data.confirmToken
  )

  await post(
    '/change-password-request', {
      email: 'david@scalehaus.io',
      changeUrl: 'http://example.com/change'
    }
  )

  const res = await post(
    '/change-password',
    postData
  )

  t.is(res.status, 401)

  var data = await res.json()
  t.is(data.success, false, 'should not succeed')
  t.is(data.error, 'Token Mismatch', 'should have error')
  t.notOk((data.data || {}).authToken, 'should not have token')
})

test('Auth: Change Password: should change password and login', async (t) => {
  Users.reset()

  const u = await Users.createUserAsync(
    'david@scalehaus.io',
    'dsfdsfdsf345'
  )

  await Users.confirmUserAsync(
    'david@scalehaus.io',
    u.data.confirmToken
  )

  await post(
    '/change-password-request', {
      email: 'david@scalehaus.io',
      changeUrl: 'http://example.com/change'
    }
  )

  const user = await Users.findUserAsync('david@scalehaus.io')

  var postData = {
    email: 'david@scalehaus.io',
    changeToken: user.data.changeToken,
    password: 'newpass'
  }

  const res = await post('/change-password', postData)

  t.is(res.status, 200)

  var data = await res.json()
  t.is(data.success, true, 'should succeed')
  t.is(data.message, 'Password changed.', 'should have message')

  const payload = await tokens.decodeAsync(data.data.authToken)

  t.is(payload.email, 'david@scalehaus.io', 'payload should have email')
  t.ok(payload.iat, 'should have iat')
  t.ok(payload.exp, 'should have exp')
})

test('Auth: Change Password: should error with expired token', async (t) => {
  var postData = {
    email: 'david@scalehaus.io',
    changeToken: 'expired token',
    password: 'newpass2'
  }

  Users.reset()

  const u = await Users.createUserAsync(
    'david@scalehaus.io',
    'dsfdsfdsf345'
  )

  await Users.confirmUserAsync(
    'david@scalehaus.io',
    u.data.confirmToken
  )

  const res = await post('/change-password', postData)

  t.is(res.status, 400)

  var data = await res.json()
  t.is(data.success, false, 'should not succeed')
  t.is(data.error, 'Token Expired', 'should have error')
  t.notOk((data.data || {}).authToken, 'should not have token')
})
