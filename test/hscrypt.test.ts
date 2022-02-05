import { encrypt, decrypt } from '../src/hscrypt'

test('encryption/decryption round-trip', () => {
    const source = `var abc = 123;
var def = "😎"
function abcdef() {
    return abc + def
}`

    const pswd = 'my-password'
    const iterations = 1000
    const encrypted = encrypt({ source, pswd, iterations, })
    const decrypted = decrypt({ encrypted, pswd, iterations, })

    expect(decrypted).toBe(source);
});
