import { encrypt } from '../src/encrypt'
import { _decrypt } from '../src/hscrypt'

test('encryption/decryption round-trip', () => {
    const source = `var abc = 123;
var def = "😎"
function abcdef() {
    return abc + def
}`

    const pswd = 'my-password'
    const iterations = 1000
    const encrypted = encrypt({ source, pswd, iterations, })
    const decrypted = _decrypt({ encrypted, pswd, iterations, })

    expect(decrypted.source).toBe(source);
});
