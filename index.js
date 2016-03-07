import { withOptions } from './src'
import { readFileSync } from 'fs'
import { join } from 'path'

export default withOptions({
  publicKey: readFileSync(join(__dirname, 'test/fixtures/rsa-public.pem')),
  privateKey: readFileSync(join(__dirname, 'test/fixtures/rsa-private.pem'))
})
