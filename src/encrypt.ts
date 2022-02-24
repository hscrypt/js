import CryptoJS from "crypto-js";
import {toUint8Array} from "./crypto";
import { toHexString, Source, SALT_LENGTH, NONCE_LENGTH, DEFAULT_ITERATIONS, DECRYPTION_KEY_LENGTH, SOURCE_PREFIX_ARRAY } from "./utils"
import { Chacha20 } from "ts-chacha20";

export function encrypt({ source, pswd, iterations, }: {
    source: Source
    pswd: string
    iterations?: number
}): Uint8Array {
    iterations = iterations || DEFAULT_ITERATIONS
    const salt = CryptoJS.lib.WordArray.random(SALT_LENGTH)
    const saltBuf = toUint8Array(salt)
    console.time('PBKDF2')
    const decryptionKey = toUint8Array(CryptoJS.PBKDF2(pswd, salt, { hasher: CryptoJS.algo.SHA512, keySize: DECRYPTION_KEY_LENGTH / 4, iterations }))
    console.timeEnd('PBKDF2')
    const nonce = toUint8Array(CryptoJS.lib.WordArray.random(NONCE_LENGTH))

    console.log(`salt: ${toHexString(saltBuf)}`)
    console.log(`nonce: ${toHexString(nonce)}`)
    console.log(`decryptionKey: ${toHexString(decryptionKey)}`)
    console.log(`iterations: ${iterations}`)

    const encoder = new Chacha20(decryptionKey, nonce)

    const sourceArray = typeof source === 'string' ? new TextEncoder().encode(source) : source
    const prefixedSourceArray = new Uint8Array([ ...SOURCE_PREFIX_ARRAY, ...sourceArray ])

    console.time('ChaCha20')
    const ciphertext = encoder.encrypt(prefixedSourceArray)
    console.timeEnd('ChaCha20')

    const encrypted = new Uint8Array(saltBuf.length + nonce.length + ciphertext.length)
    encrypted.set(saltBuf, 0)
    encrypted.set(nonce, saltBuf.length)
    encrypted.set(ciphertext, saltBuf.length + nonce.length)

    return encrypted
}
