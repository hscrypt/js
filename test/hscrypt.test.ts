import { encrypt, decrypt } from '../src/hscrypt'

test('encryption/decryption round-trip', () => {
    const source = `var abc = 123;
var def = "😎"
function abcdef() {
    return abc + def
}`

    const pswd = 'my-password'
    const encrypted = encrypt({ source, pswd })
    const decrypted = decrypt({ encrypted, pswd })

    expect(decrypted).toBe(source);
});
