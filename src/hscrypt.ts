import CryptoJS from "crypto-js";
import { Chacha20 } from "ts-chacha20";

import { toUint8Array, convertUint8ArrayToWordArray } from "./crypto"
import { fromHexString, toHexString, SALT_LENGTH, NONCE_LENGTH, DEFAULT_ITERATIONS, SECRET_KEY_LENGTH, SOURCE_PREFIX } from "./utils"

function checkStatus(response: Response) {
    if (!response.ok) {
        throw new Error(`HTTP ${response.status} - ${response.statusText}`);
    }
    return response;
}

export function getLocalStorageKey() {
    const path = window.location.pathname
    return `hscrypt.secret:${path}`
}

class DecryptionError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "DecryptionError";
    }
}

export function inject({ src, pswd, iterations, cache, catchFn, decryptionErrorFn, scrubHash, }: {
    src: string
    pswd: string
    iterations: number
    cache: boolean
    catchFn?: () => void
    decryptionErrorFn?: (err: DecryptionError, cacheHit: boolean) => void
    scrubHash?: boolean
}) {
    if (scrubHash === undefined) {
        scrubHash = cache
    }

    let secretHex: string
    if (!pswd) {
        const hash = document.location.hash
        if (hash && hash.length > 1) {
            pswd = hash.substring(1)
            if (scrubHash) {
                console.log("Scrubbing password from URL fragment")
                document.location.hash = ''
            }
        }
    }

    const localStorageKey = getLocalStorageKey()

    let cacheHit = false
    if (!pswd && cache) {
        let secretHex = localStorage.getItem(localStorageKey)
        if (secretHex) {
            console.log("Read secretHex from cache:", secretHex)
            cacheHit = true
        }
    }

    if (!pswd && !secretHex) {
        if (catchFn) {
            catchFn()
            return
        } else {
            alert("Password required")
            //document.body.innerHTML += `<div style="color: red;font-size:2em">Password required</div>`
            throw new Error("Password required")
        }
    }

    return fetch(src)
        .then(response => {
            checkStatus(response)
            return response.arrayBuffer().then(buf => new Uint8Array(buf))
        })
        .then(encrypted => {
            try {
                const { source, secret } = decrypt({encrypted, pswd, iterations, secretHex,})
                if (cache && !secretHex) {
                    secretHex = toHexString(secret)
                    localStorage.setItem(localStorageKey, secretHex)
                    console.log(`Saved secretHex, ${localStorageKey}: ${secretHex}`)
                }

                // console.log(`hscrypt: injecting ${source}`)
                const script = document.createElement('script')
                script.setAttribute("type", "text/javascript")
                script.innerHTML = source
                document.body.appendChild(script)
            } catch (err) {
                if (err instanceof DecryptionError) {
                    if (cacheHit) {
                        console.log(`Clearing cache key ${localStorageKey} after unsuccessful decryption of cached secretHex`)
                        localStorage.deleteItem(localStorageKey)
                    }
                    if (decryptionErrorFn) {
                        decryptionErrorFn(err, cacheHit)
                    } else {
                        const msg = cacheHit ? `Decryption failed (from cache): ${err.message}` : `Decryption failed: ${err.message}`
                        alert(msg)
                        throw err
                    }
                    return
                } else {
                    throw err
                }
            }
        })
}

export function decrypt({ encrypted, pswd, iterations, secretHex, }: {
    encrypted: Uint8Array,
    pswd: string,
    iterations?: number,
    secretHex?: string,
}): { source: string, secret: Uint8Array } {
    let secret: Uint8Array
    const nonce = encrypted.slice(SALT_LENGTH, SALT_LENGTH + NONCE_LENGTH)
    const ciphertext = encrypted.slice(SALT_LENGTH + NONCE_LENGTH)
    iterations = iterations || DEFAULT_ITERATIONS
    if (secretHex) {
        secret = fromHexString(secretHex)
    } else {
        console.log(`decrypting: ${iterations} iterations`)
        const saltBuf = encrypted.slice(0, SALT_LENGTH)
        console.log(`  salt: ${toHexString(saltBuf)}`)
        // console.log(`  pswd: ${pswd}`)
        const salt = convertUint8ArrayToWordArray(saltBuf)
        secret = toUint8Array(CryptoJS.PBKDF2(pswd, salt, {
            hasher: CryptoJS.algo.SHA512,
            keySize: SECRET_KEY_LENGTH / 4,
            iterations: iterations || DEFAULT_ITERATIONS
        }))
    }
    console.log(` nonce: ${toHexString(nonce)}`)
    console.log(`secret: ${toHexString(secret)}`)
    console.log(`iterations: ${iterations}`)
    const decoder = new Chacha20(secret, nonce)
    const plaintext = new TextDecoder().decode(decoder.decrypt(ciphertext))
    const prefix = plaintext.substring(0, SOURCE_PREFIX.length)
    if (prefix != SOURCE_PREFIX) {
        throw new DecryptionError(`Invalid prefix: ${prefix}`)
    }
    const source = plaintext.substring(SOURCE_PREFIX.length)
    return { source, secret }
}
