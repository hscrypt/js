import CryptoJS from "crypto-js";
import {toUint8Array} from "./crypto";
import { toHexString, SALT_LENGTH, NONCE_LENGTH, DEFAULT_ITERATIONS, SECRET_KEY_LENGTH, SOURCE_PREFIX } from "./utils"
import { Chacha20 } from "ts-chacha20";

export function encrypt({ source, pswd, iterations, }: {
    source: string | Buffer,
    pswd: string,
    iterations?: number
}): Uint8Array {
    iterations = iterations || DEFAULT_ITERATIONS
    const salt = CryptoJS.lib.WordArray.random(SALT_LENGTH)
    const saltBuf = toUint8Array(salt)
    const secret = toUint8Array(CryptoJS.PBKDF2(pswd, salt, { hasher: CryptoJS.algo.SHA512, keySize: SECRET_KEY_LENGTH / 4, iterations }))
    const nonce = toUint8Array(CryptoJS.lib.WordArray.random(NONCE_LENGTH))

    console.log(`  salt: ${toHexString(saltBuf)}`)
    console.log(` nonce: ${toHexString(nonce)}`)
    console.log(`secret: ${toHexString(secret)}`)
    console.log(`iterations: ${iterations}`)

    const encoder = new Chacha20(secret, nonce)

    source = `${SOURCE_PREFIX}${source}`
    const input = (typeof source === 'string') ? new TextEncoder().encode(source) : source
    const ciphertext = encoder.encrypt(input)

    const encrypted = new Uint8Array(saltBuf.length + nonce.length + ciphertext.length)
    encrypted.set(saltBuf, 0)
    encrypted.set(nonce, saltBuf.length)
    encrypted.set(ciphertext, saltBuf.length + nonce.length)

    return encrypted
}
