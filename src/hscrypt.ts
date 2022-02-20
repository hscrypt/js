import CryptoJS from "crypto-js";
import { Chacha20 } from "ts-chacha20";

import { toUint8Array, convertUint8ArrayToWordArray } from "./crypto"
import { fromHexString, toHexString, SALT_LENGTH, NONCE_LENGTH, DEFAULT_ITERATIONS, SECRET_KEY_LENGTH, SOURCE_PREFIX } from "./utils"
export { encrypt } from "./encrypt"

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

export class DecryptionError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "DecryptionError";
    }
}

export type MsgCb<T> = (args: T) => void
export type MissingKeyCb = MsgCb<{ msg: string }>
export type DecryptionErrorCb = MsgCb<{ err: DecryptionError, cacheHit: boolean }>

export type InjectConfig = {
    src: string
    pswd: string
    iterations: number
    cache: boolean
    missingKeyCb?: MissingKeyCb | string
    decryptionErrorCb?: DecryptionErrorCb | string
    scrubHash?: boolean
    watchHash?: boolean
}

function getCb<T>(cb: MsgCb<T> | string): MsgCb<T> {
    if (typeof cb === 'string') {
        const pieces = cb.split('.')
        const fn: MsgCb<T> = pieces.reduce<{ [k: string]: any }>((obj, k) => obj && obj[k], window) as any
        return fn
    } else {
        return cb
    }

}

export function inject({ src, pswd, iterations, cache, missingKeyCb, decryptionErrorCb, scrubHash, watchHash, }: InjectConfig) {
    // In the common case, the `pswd` argument is empty, and we look for it in the URL "hash"
    let secretHex: string
    if (!pswd) {
        const hash = document.location.hash
        if (hash && hash.length > 1) {
            pswd = hash.substring(1)
            // By default, "scrub" (remove) the password from the URL hash (after reading+storing it)
            if (scrubHash || scrubHash === undefined) {
                console.log("Scrubbing password from URL fragment")
                document.location.hash = ''
            }
        }
    }

    // Optionally watch for changes to the URL hash; re-attempt decryption if found. If successful decryption occurs on
    // this pass, this listener is immediately removed
    let hashListener: (() => void) | undefined
    if (watchHash || watchHash === undefined) {
        hashListener = () => {
            console.log("Detected hash change, re-injecting")
            inject({ src, pswd: null, iterations, cache, missingKeyCb, decryptionErrorCb, scrubHash, watchHash: false, })
        }
        window.addEventListener("hashchange", hashListener, false);
        console.log(`Added hashListener: ${hashListener}`)
    }

    // If `cache` is true, the `secretHex` (post-PBKDF2) is cached in localStorage under a key that is unique to the
    // current URL "pathname" component (all of `localStorage` is assumed to be specific to the current "hostname").
    // Caching post-PBKDF2 secret material allows for faster reloads of previously decrypted pages.
    const localStorageKey = getLocalStorageKey()

    let cacheHit = false
    if (!pswd && cache) {
        secretHex = localStorage.getItem(localStorageKey)
        if (secretHex) {
            console.log("Read secretHex from cache:", secretHex)
            cacheHit = true
        }
    }

    // If no decryption key was provided explicitly or found in the `localStorage` cache, we're essentially in an error
    // state (though the exact semantics are up to the containing application; a friendly "please enter the password"
    // page, or even an app with reduced functionality/data, may be desired).
    // `missingKeyCb` is invoked here (defaulting to `console.log`, but a string like "MyApp.myMissingKeyCb" can be
    // provided as well)
    if (!pswd && !secretHex) {
        const msg = "Please provide a password / decryption key as a URL hash"
        if (!missingKeyCb) {
            missingKeyCb = ({ msg: string }) => console.log(msg)
        }
        const cb = getCb(missingKeyCb)
        cb({ msg })
        return
    }

    // Fetch + Decrypt the remote+encrypted source bundle
    return fetch(src)
        .then(response => {
            checkStatus(response)
            return response.arrayBuffer().then(buf => new Uint8Array(buf))
        })
        .then(encrypted => {
            try {
                const { source, secret } = decrypt({encrypted, pswd, iterations, secretHex,})
                if (cache && !secretHex) {
                    // Cache the post-PBKDF2 secret material for faster subsequent reloads
                    secretHex = toHexString(secret)
                    localStorage.setItem(localStorageKey, secretHex)
                    console.log(`Saved secretHex, ${localStorageKey}: ${secretHex}`)
                }

                // Inject the decrypted source by appending to document.body. TODO: make this configurable?
                console.log(`hscrypt: injecting source from ${src}`)
                const script = document.createElement('script')
                script.setAttribute("type", "text/javascript")
                script.innerHTML = source
                document.body.appendChild(script)

                // Remove any `hashListener`, if one was added
                if (hashListener) {
                    console.log("Removing hashListener")
                    window.removeEventListener("hashchange", hashListener, false)
                }
            } catch (err) {
                console.log(`Caught: ${err} (${err instanceof DecryptionError}), ${err.name}`)
                if (err instanceof DecryptionError) {
                    // DecryptionError can result from:
                    // 1. secret material was cached in `localStorage` for a previous version of this URL, and is now
                    //    out of date (secret was read from cache, where it would only have been stored after a previous
                    //    successful decryption, but now decryption has failed), or
                    // 2. password provided in this decryption invocation failed to decrypt the ciphertext (password is
                    //    incorrect, presumably)
                    //
                    // In the first case, we clear the cache entry, and in either case we invoke the `decryptionErrorCb`
                    // (defaults to `alert` + `throw`, but can be passed a string like "MyApp.myDecryptionErrorCb").
                    console.log(`Caught DecryptionError: ${err}`)
                    if (cacheHit) {
                        console.log(`Clearing cache key ${localStorageKey} after unsuccessful decryption of cached secretHex`)
                        localStorage.removeItem(localStorageKey)
                    }
                    const msg =
                        cacheHit
                            ? `Decryption failed: ${err.message} (bad / out of date cache; clearing)`
                            : `Decryption failed: ${err.message} (wrong password?)`
                    if (!decryptionErrorCb) {
                        decryptionErrorCb = ({ err: DecryptionError, cacheHit: boolean }) => {
                            alert(msg)
                            throw err
                        }
                    }
                    const cb = getCb(decryptionErrorCb)
                    cb({ err, cacheHit })
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
        // If the secret is already known + passed in, we can skip the expensive PBKDF2 step
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

    // If decryption was successful, the plaintext will begin with the `SOURCE_PREFIX` magic bytes ("/* hscrypt */ ")
    const prefix = plaintext.substring(0, SOURCE_PREFIX.length)
    if (prefix != SOURCE_PREFIX) {
        throw new DecryptionError(`Invalid prefix: ${prefix}`)
    }
    const source = plaintext.substring(SOURCE_PREFIX.length)
    return { source, secret }
}
