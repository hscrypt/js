import { randomBytes, pbkdf2Sync } from "crypto"

import ChaCha20 from "ts-chacha20";

function checkStatus(response: Response) {
    if (!response.ok) {
        throw new Error(`HTTP ${response.status} - ${response.statusText}`);
    }
    return response;
}

export function inject(src: string, pswd: string) {
    if (!pswd) {
        throw new Error("Password required")
    }
    const hash = document.location.hash
    pswd = hash.substring(1)
    return fetch(src)
        .then(response => {
            checkStatus(response)
            return response.arrayBuffer().then(buf => new Uint8Array(buf))
        })
        .then(encrypted => {
            const source = decrypt({ encrypted, pswd, })
            console.log(`hscrypt: injecting ${source}`)
            const script = document.createElement('script')
            script.setAttribute("type", "text/javascript")
            script.innerHTML = source
            document.body.appendChild(script)
        })
}

const SECRET_KEY_LENGTH = 32
const DIGEST = 'sha512'
const DEFAULT_ITERATIONS = 100_000
const SALT_LENGTH = 32
const NONCE_LENGTH = 12

export function encrypt({ source, pswd, iterations, }: {
    source: string,
    pswd: string,
    iterations?: number
}): Uint8Array {
    const salt = randomBytes(SALT_LENGTH)
    const secret = pbkdf2Sync(pswd, salt, iterations || DEFAULT_ITERATIONS, SECRET_KEY_LENGTH, DIGEST)
    const nonce = randomBytes(NONCE_LENGTH)

    const encoder = new ChaCha20(secret, nonce)

    const input = new TextEncoder().encode(source)
    const ciphertext = encoder.encrypt(input)

    const encrypted = new Uint8Array(salt.length + nonce.length + ciphertext.length)
    encrypted.set(salt, 0)
    encrypted.set(nonce, salt.length)
    encrypted.set(ciphertext, salt.length + nonce.length)

    return encrypted
}

export function decrypt({ encrypted, pswd, iterations, }: {
    encrypted: Uint8Array,
    pswd: string,
    iterations?: number,
}): string {
    const salt = encrypted.slice(0, SALT_LENGTH)
    const nonce = encrypted.slice(SALT_LENGTH, SALT_LENGTH + NONCE_LENGTH)
    const ciphertext = encrypted.slice(SALT_LENGTH + NONCE_LENGTH)
    const secret = pbkdf2Sync(pswd, salt, iterations || DEFAULT_ITERATIONS, SECRET_KEY_LENGTH, DIGEST)

    const decoder = new ChaCha20(secret, nonce)
    const source = new TextDecoder().decode(decoder.decrypt(ciphertext))

    return source
}
