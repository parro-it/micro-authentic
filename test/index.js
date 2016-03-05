var fs = require('fs')
var http = require('http')
var test = require('ava')
var servertest = require('servertest')

var Authentic = require('../')

var Users = require('../users')()

var publicKey = fs.readFileSync(__dirname + '/fixtures/rsa-public.pem')
var privateKey = fs.readFileSync(__dirname + '/fixtures/rsa-private.pem')

var Tokens = require('../tokens')({
  publicKey: publicKey,
  privateKey: privateKey
})

var lastEmail

var auth = Authentic({
  publicKey: publicKey,
  privateKey: privateKey,
  sendEmail: function (email, cb) {
    lastEmail = email
    setImmediate(cb)
  }
})

test('Auth: should get public-key', function (t) {
  var url = '/auth/public-key'
  var opts = { method: 'GET' }

  servertest(createServer(auth), url, opts, function (err, res) {
    t.ifError(err, 'should not error')
    var data = JSON.parse(res.body)

    t.equal(data.success, true, 'should succeed')
    t.equal(data.data.publicKey.length, 800, 'should have publicKey')

    t.end()
  })
})

test('Auth: Signup: should be able to sign up', function (t) {
  var postData = {email: 'david@scalehaus.io', password: 'swordfish', confirmUrl: 'http://example.com/confirm'}

  post('/auth/signup', postData, function (err, res) {
    t.ifError(err, 'should not error')

    t.equal(res.statusCode, 201)

    var data = JSON.parse(res.body)
    t.equal(data.success, true, 'should succeed')
    t.equal(data.message, 'User created. Check email for confirmation link.', 'should have message')
    t.equal(data.data.email, 'david@scalehaus.io', 'should have email')
    t.equal(data.data.createdDate.length, 24, 'should have createdDate')

    t.end()
  })
})

test('Auth: Login: should fail without confirm', function (t) {
  var postData = {email: 'david@scalehaus.io', password: 'swordfish'}

  post('/auth/login', postData, function (err, res) {
    t.ifError(err, 'should not error')

    t.equal(res.statusCode, 401)

    var data = JSON.parse(res.body)
    t.equal(data.success, false, 'should not succeed')
    t.equal(data.error, 'User Not Confirmed', 'should have error')

    t.end()
  })
})

test('Auth: Signup: sendEmail should get email options', function (t) {
  var postData = {
    email: 'email@scalehaus.io',
    password: 'swordfish',
    confirmUrl: 'http://example.com/confirm',
    from: 'from@somewhere.com',
    subject: 'Client Defined Subject',
    html: '<h1>Welcome</h1><p><a href="{{confirmUrl}}">Confirm</a></p>'
  }

  post('/auth/signup', postData, function (err, res) {
    t.ifError(err, 'should not error')
    t.equal(res.statusCode, 201)

    t.notOk(lastEmail.password, 'should not have password')
    t.equal(lastEmail.from, postData.from, 'should have from')
    t.equal(lastEmail.subject, postData.subject, 'should have subject')
    t.equal(lastEmail.html, postData.html, 'should have html')

    t.end()
  })
})

test('Auth: Signup: should error for existing user', function (t) {
  var postData = {email: 'david@scalehaus.io', password: 'swordfish', confirmUrl: 'http://example.com/confirm'}

  post('/auth/signup', postData, function (err, res) {
    t.ifError(err, 'should not error')

    t.equal(res.statusCode, 400)

    var data = JSON.parse(res.body)
    t.notEqual(data.success, true, 'should not succeed')
    t.equal(data.error, 'User Exists', 'should have error')

    t.end()
  })
})

test('Auth: Confirm: should error for mismatch', function (t) {
  var postData = {email: 'david@scalehaus.io', confirmToken: 'incorrect'}

  post('/auth/confirm', postData, function (err, res) {
    t.ifError(err, 'should not error')

    t.equal(res.statusCode, 401)

    var data = JSON.parse(res.body)
    t.equal(data.success, false, 'should not succeed')
    t.equal(data.error, 'Token Mismatch')

    t.end()
  })
})

test('Auth: Confirm: should confirm user', function (t) {
  Users.createUser('david@scalehaus.io', '', (err2, user) => {
    Users.findUser('david@scalehaus.io', function (err, user) {
      t.ifError(err, 'should not error')

      var postData = {
        email: 'david@scalehaus.io',
        confirmToken: user.data.confirmToken
      }

      post('/auth/confirm', postData, function (err, res) {
        t.ifError(err, 'should not error')

        t.equal(res.statusCode, 202)

        var data = JSON.parse(res.body)
        t.equal(data.success, true, 'should succeed')
        t.equal(data.message, 'User confirmed.', 'should have message')

        Tokens.decode(data.data.authToken, function (err, payload) {
          t.ifError(err, 'should not error')

          t.equal(payload.email, 'david@scalehaus.io', 'payload should have email')
          t.ok(payload.iat, 'should have iat')

          t.end()
        })
      })
    })
  })
})

test('Auth: Login: should error for unknown user', function (t) {
  var postData = {
    email: 'notdavid@scalehaus.io',
    password: 'not swordfish'
  }

  post('/auth/login', postData, function (err, res) {
    t.ifError(err, 'should not error')

    t.equal(res.statusCode, 401)

    var data = JSON.parse(res.body)
    t.equal(data.success, false, 'should not succeed')
    t.equal(data.error, 'User Not Found', 'should have error message')

    t.end()
  })
})

test('Auth: Login: should error for wrong pass', function (t) {
  var postData = {
    email: 'david@scalehaus.io',
    password: 'not swordfish'
  }

  post('/auth/login', postData, function (err, res) {
    t.ifError(err, 'should not error')

    t.equal(res.statusCode, 401)

    var data = JSON.parse(res.body)
    t.equal(data.success, false, 'should not succeed')
    t.equal(data.error, 'Password Mismatch', 'should have error message')

    t.end()
  })
})

test('Auth: Login: should login', function (t) {
  Users.createUser('david@scalehaus.io', 'swordfish', (err2, user) => {
    Users.confirmUser('david@scalehaus.io', user.confirmToken, (err3) => {
      var postData = {
        email: 'david@scalehaus.io',
        password: 'swordfish'
      }

      post('/auth/login', postData, function (err, res) {
        t.ifError(err, 'should not error')

        t.equal(res.statusCode, 202)

        var data = JSON.parse(res.body)
        t.equal(data.success, true, 'should succeed', 'should succeed')
        t.equal(data.message, 'Login successful.', 'should have message')

        Tokens.decode(data.data.authToken, function (err, payload) {
          t.ifError(err, 'should not error')

          t.equal(payload.email, 'david@scalehaus.io', 'payload should have email')
          t.ok(payload.iat, 'should have iat')
          t.ok(payload.exp, 'should have exp')
          t.end()
        })
      })
    })
  })
})

test('Auth: Change Password Request', function (t) {
  var postData = {email: 'david@scalehaus.io', changeUrl: 'http://example.com/change'}

  post('/auth/change-password-request', postData, function (err, res) {
    t.ifError(err, 'should not error')

    t.equal(res.statusCode, 200)

    var data = JSON.parse(res.body)
    t.ok(data.success, 'should succeed')
    t.equal(data.message, 'Change password request received. Check email for confirmation link.')
    Users.createUser('david@scalehaus.io', '', (err2, user) => {
      Users.findUser(postData.email, function (err, user) {
        t.ifError(err, 'should not error')

        t.equal(user.data.emailConfirmed, true, 'email should be confirmed')
        t.equal(user.data.changeToken.length, 60, 'should have change token')
        t.ok(user.data.changeExpires > Date.now(), 'should have changeExpires')

        t.end()
      })
    })
  })
})

test('Auth: Change Password Request should fix case', function (t) {
  var postData = {email: 'TitleCase24@scalehaus.io', changeUrl: 'http://example.com/change'}

  post('/auth/change-password-request', postData, function (err, res) {
    t.ifError(err, 'should not error')

    t.equal(res.statusCode, 200)

    var data = JSON.parse(res.body)
    t.ok(data.success, 'should succeed')
    t.equal(data.message, 'Change password request received. Check email for confirmation link.')
    Users.createUser('david@scalehaus.io', '', (err2, user) => {
      Users.findUser(postData.email.toLowerCase(), function (err, user) {
        t.ifError(err, 'should not error')

        t.equal(user.data.emailConfirmed, true, 'email should be confirmed')
        t.equal(user.data.changeToken.length, 60, 'should have change token')
        t.ok(user.data.changeExpires > Date.now(), 'should have changeExpires')

        t.end()
      })
    })
  })
})

test('Auth: Change Password Request: will create confirmed user', t => {
  var postData = {email: 'unknownuser@scalehaus.io', changeUrl: 'http://example.com/change'}

  post('/auth/change-password-request', postData, (err, res) => {
    t.ifError(err, 'should not error')

    t.equal(res.statusCode, 200)

    var data = JSON.parse(res.body)
    t.ok(data.success, 'should succeed')
    t.equal(data.message, 'Change password request received. Check email for confirmation link.')

    Users.createUser(postData.email, '', (err2, user2) => {
      Users.findUser(postData.email, function (err, user) {
        t.ifError(err, 'should not error')

        t.equal(user.data.emailConfirmed, true, 'email should be confirmed')
        t.equal(user.data.changeToken.length, 60, 'should have change token')
        t.ok(user.data.changeExpires > Date.now(), 'should have changeExpires')

        t.end()
      })
    })
  })
})

test('Auth: Change Password Request: sendEmail should get email options', function (t) {
  var postData = {
    email: 'email@scalehaus.io',
    changeUrl: 'http://example.com/change',
    from: 'from@somewhere.com',
    subject: 'Change PW Subject',
    html: '<h1>Change PW</h1><p><a href="{{changeUrl}}">Change</a></p>'
  }

  post('/auth/change-password-request', postData, function (err, res) {
    t.ifError(err, 'should not error')
    t.equal(res.statusCode, 200)

    t.equal(lastEmail.from, postData.from, 'should have from')
    t.equal(lastEmail.subject, postData.subject, 'should have subject')
    t.equal(lastEmail.html, postData.html, 'should have html')

    t.end()
  })
})

test('Auth: Change Password: should error with wrong token', function (t) {
  var postData = {
    email: 'david@scalehaus.io',
    changeToken: 'wrong token',
    password: 'newpass'
  }

  post('/auth/change-password', postData, function (err, res) {
    t.ifError(err, 'should not error')

    t.equal(res.statusCode, 401)

    var data = JSON.parse(res.body)
    t.equal(data.success, false, 'should not succeed')
    t.equal(data.error, 'Token Mismatch', 'should have error')
    t.notOk((data.data || {}).authToken, 'should not have token')

    t.end()
  })
})

test('Auth: Change Password: should change password and login', function (t) {
  Users.createUser('david@scalehaus.io', '', (err2, user) => {
    Users.findUser('david@scalehaus.io', function (err, user) {
      t.ifError(err, 'should not error')

      var postData = {
        email: 'david@scalehaus.io',
        changeToken: user.data.changeToken,
        password: 'newpass'
      }

      post('/auth/change-password', postData, function (err, res) {
        t.ifError(err, 'should not error')

        t.equal(res.statusCode, 200)

        var data = JSON.parse(res.body)
        t.equal(data.success, true, 'should succeed')
        t.equal(data.message, 'Password changed.', 'should have message')

        Tokens.decode(data.data.authToken, function (err, payload) {
          t.ifError(err, 'should not error')

          t.equal(payload.email, 'david@scalehaus.io', 'payload should have email')
          t.ok(payload.iat, 'should have iat')
          t.ok(payload.exp, 'should have exp')
          t.end()
        })
      })
    })
  })
})

test('Auth: Change Password: should error with expired token', function (t) {
  var postData = {
    email: 'david@scalehaus.io',
    changeToken: 'expired token',
    password: 'newpass2'
  }

  post('/auth/change-password', postData, function (err, res) {
    t.ifError(err, 'should not error')

    t.equal(res.statusCode, 400)

    var data = JSON.parse(res.body)
    t.equal(data.success, false, 'should not succeed')
    t.equal(data.error, 'Token Expired', 'should have error')
    t.notOk((data.data || {}).authToken, 'should not have token')

    t.end()
  })
})

function post (url, data, cb) {
  var opts = {
    method: 'POST',
    headers: {'content-type': 'application/json'}
  }

  servertest(createServer(auth), url, opts, cb).end(JSON.stringify(data))
}

function createServer (auth) { return http.createServer(auth) }
