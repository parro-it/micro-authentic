import micro, {send} from 'micro'

function onError (req, res, err) {
  if (!err) return

  send(res, err.statusCode || 500, {
    success: false,
    error: err.message
  })
}

export default async function listen (fn) {
  const srv = micro(fn, {onError})
  return new Promise((resolve, reject) => {
    srv.listen((err) => {
      if (err) return reject(err)
      const { port } = srv.address()
      resolve(`http://localhost:${port}`)
    })
  })
}
