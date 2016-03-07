export default function error (statusCode, message) {
  const err = new Error(message)
  err.statusCode = statusCode
  throw err
}
