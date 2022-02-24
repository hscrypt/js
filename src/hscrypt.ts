import CryptoJS from "crypto-js";
import { Chacha20 } from "ts-chacha20";

import { toUint8Array, convertUint8ArrayToWordArray } from "./crypto"
import {
    fromHexString,
    toHexString,
    Source,
    SALT_LENGTH,
    NONCE_LENGTH,
    DEFAULT_ITERATIONS,
    DECRYPTION_KEY_LENGTH,
    SOURCE_PREFIX,
    HSCRYPT_CONFIG_VAR
} from "./utils"
import { getLocalStorageKey } from "./cache"

export { DEFAULT_ITERATIONS, HSCRYPT_CONFIG_VAR, SOURCE_PREFIX, SOURCE_PREFIX_ARRAY, Source } from "./utils"
export { LOCALSTORAGE_PREFIX, getLocalStorageKey, getCachedDecryptionKey, clearCachedDecryptionKey, } from "./cache"
export { encrypt } from "./encrypt"

function checkStatus(response: Response) {
    if (!response.ok) {
        throw new Error(`HTTP ${response.status} - ${response.statusText}`);
    }
    return response;
}

export class DecryptionError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "DecryptionError";
    }
}

export type Cb<T> = (args: T) => void
export type CbRef<T> = Cb<T> | string
export type MissingKeyCbArgs = { msg: string }
export type DecryptionErrorCbArgs = { err: DecryptionError, cacheHit: boolean }

export type Decrypt = {
    src?: string
    iterations?: number
    decryptionKeyHex?: string
    cacheDecryptionKey?: boolean
    cacheHit?: boolean
    decryptionErrorCb?: CbRef<DecryptionErrorCbArgs>
    hashListener?: () => void
}
export type FetchAndDecrypt = {
    src: string
    pswd: string

    iterations?: number
    decryptionKeyHex?: string
    cacheDecryptionKey?: boolean
    cacheHit?: boolean
    decryptionErrorCb?: CbRef<DecryptionErrorCbArgs>
    hashListener?: () => void
}
export type DecryptAndCache = {
    encrypted: Uint8Array
    pswd: string

    iterations?: number
    decryptionKeyHex?: string
    cacheDecryptionKey?: boolean
    cacheHit?: boolean
    decryptionErrorCb?: CbRef<DecryptionErrorCbArgs>
    hashListener?: () => void
}

export type InjectConfig = {
    src: string
    pswd: string

    iterations?: number
    cacheDecryptionKey?: boolean
    missingKeyCb?: CbRef<MissingKeyCbArgs>
    decryptionErrorCb?: CbRef<DecryptionErrorCbArgs>
    scrubHash?: boolean
    watchHash?: boolean
}

export type _Decrypt = {
    encrypted: Uint8Array,
    pswd: string,

    iterations?: number,
    decryptionKeyHex?: string,
}

// Coerce a "callback ref" (which may be a callback function or a "."-delimited string name of a global function, e.g.
// "MyApp.myCb") to a callback
function getCb<T>(cb: CbRef<T>): Cb<T> {
    if (typeof cb === 'string') {
        const pieces = cb.split('.')
        const fn: Cb<T> = pieces.reduce<{ [k: string]: any }>((obj, k) => obj && obj[k], window) as any
        return fn
    } else {
        return cb
    }
}

export function inject({ src, pswd, iterations, cacheDecryptionKey, missingKeyCb, decryptionErrorCb, scrubHash, watchHash, }: InjectConfig) {
    // In the common case, the `pswd` argument is empty, and we look for it in the URL "hash"
    let decryptionKeyHex: string
    if (!pswd) {
        const hash = document.location.hash
        if (hash && hash.length > 1) {
            pswd = hash.substring(1)
            // By default, "scrub" (remove) the password from the URL hash (after reading+storing it)
            if (scrubHash || scrubHash === undefined) {
                console.log("Scrubbing password from URL fragment")
                const location = window.location
                const title = 'Decrypted page'
                if (!document.title) {
                    // Hscrypt makes a best effort to not store the password anywhere, but browsers seem to record it
                    // (as part of the URL hash) in their history in a way I haven't found a workaround for.
                    //
                    // Chrome and Firefox (but no Safari, afaict; other browsers as yet untested), in the absence of a
                    // page title, display the full URL (including the hash) as the tab title, somewhat prominently.
                    // Here we set a placeholder page title to avoid this, but the recommended practice is to set a
                    // <title> on hscrypt encrypted landing pages.
                    //
                    // More discussion: https://stackoverflow.com/a/41073373/544236
                    console.warn(
                        "No `document.title` set on page receiving password via URL hash; some browsers (Chrome " +
                        "and Firefox, at least) display the full URL (including hash) as the title, which creates a " +
                        "risk of \"shoulder-surfing.\" Overriding the title now, but in general it's recommended to " +
                        "set a <title> on hscrypt encrypted landing pages. Also note that the password is likely " +
                        "persisted in this browser's history as part of the page's location."
                    )
                    document.title = title
                }
                history.replaceState(null, title, location.pathname + location.search)
            }
        }
    }

    // If `cache` is true, the `decryptionKeyHex` (post-PBKDF2) is cached in localStorage under a key that is unique to the
    // current URL "pathname" component (all of `localStorage` is assumed to be specific to the current "hostname").
    // Caching the post-PBKDF2 decryption key allows for faster reloads of previously decrypted pages.
    const localStorageKey = cacheDecryptionKey ? getLocalStorageKey() : undefined

    let cacheHit = false
    if (!pswd && cacheDecryptionKey) {
        decryptionKeyHex = localStorage.getItem(localStorageKey)
        if (decryptionKeyHex) {
            console.log("Read decryptionKeyHex from cache:", decryptionKeyHex)
            cacheHit = true
        }
    }

    // Optionally, and if no password or decryption key is found:
    // - Watch for changes to the URL hash.
    // - Re-attempt decryption when a new hash is detected.
    //
    // If successful decryption occurs on the current pass, this listener is immediately removed
    let hashListener: (() => void) | undefined
    if (watchHash || watchHash === undefined) {
        hashListener = () => {
            console.log("Detected hash change, re-injecting")
            inject({src, pswd: null, iterations, cacheDecryptionKey, missingKeyCb, decryptionErrorCb, scrubHash, watchHash: false,})
        }
        window.addEventListener("hashchange", hashListener, false);
        console.log(`Added hashListener: ${hashListener}`)
    }

    // If no decryption key was provided explicitly or found in the `localStorage` cache, we're essentially in an error
    // state (though the exact semantics are up to the containing application; a friendly "please enter the password"
    // page, or even an app with reduced functionality/data, may be desired).
    // `missingKeyCb` is invoked here (defaulting to `console.log`, but a string like "MyApp.myMissingKeyCb" can be
    // provided as well)
    if (!pswd && !decryptionKeyHex) {

        const msg = "Please provide a password / decryption key as a URL hash"
        if (!missingKeyCb) {
            missingKeyCb = ({ msg }: MissingKeyCbArgs) => console.log(msg)
        }
        const cb = getCb(missingKeyCb)
        cb({msg})
        return
    }

    return fetchAndDecrypt({ src, pswd, iterations, decryptionKeyHex: decryptionKeyHex, cacheDecryptionKey, cacheHit, decryptionErrorCb, hashListener, })
}

// Simplest entrypoint to decryption+injection from client: call with password, all other configs pulled from global
// HSCRYPT_CONFIG
export function decrypt(pswd: string, config?: Decrypt) {
    if (!pswd) {
        throw new Error("hscrypt.decrypt: password required")
    }
    const HSCRYPT_CONFIG = (window as any)[HSCRYPT_CONFIG_VAR] as any
    const c: FetchAndDecrypt = Object.assign({}, HSCRYPT_CONFIG, config, { pswd })
    console.log("Full decryption object:", config)
    return fetchAndDecrypt(c)
}

// Fetch+decrypt encrypted source bundle (and optionally cache, if `localStorageKey` is provided)
export function fetchAndDecrypt({ src, pswd, iterations, decryptionKeyHex, cacheDecryptionKey, cacheHit, decryptionErrorCb, hashListener, }: FetchAndDecrypt) {
    // Fetch + Decrypt the remote+encrypted source bundle
    console.time('fetch src')
    return fetch(src)
        .then(response => {
            console.timeEnd('fetch src')
            checkStatus(response)
            return response.arrayBuffer().then(buf => new Uint8Array(buf))
        })
        .then(encrypted => {
            decryptAndCache({ encrypted, pswd, iterations, decryptionKeyHex: decryptionKeyHex, cacheDecryptionKey, cacheHit, decryptionErrorCb, hashListener, })
        })
}

// Decrypt ciphertext, optionally cache decryption key in `localStorage`
export function decryptAndCache({ encrypted, pswd, iterations, decryptionKeyHex, cacheDecryptionKey, cacheHit, decryptionErrorCb, hashListener, }: DecryptAndCache ) {
    const localStorageKey = getLocalStorageKey()
    try {
        const { source, decryptionKey } = _decrypt({ encrypted, pswd, iterations, decryptionKeyHex, })
        if (cacheDecryptionKey && !decryptionKeyHex) {
            // Cache the post-PBKDF2 decryption key for faster subsequent reloads
            decryptionKeyHex = toHexString(decryptionKey)
            localStorage.setItem(localStorageKey, decryptionKeyHex)
            console.log(`Saved decryptionKeyHex, ${localStorageKey}: ${decryptionKeyHex}`)
        }

        // Inject the decrypted source by appending to document.body. TODO: make this configurable?
        console.log(`hscrypt: injecting source`)
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
            // 1. decryption key was cached in `localStorage` for a previous version of this URL, and is now out of date
            //    (decryption key was read from cache, where it would only have been stored after a previous
            //    successful decryption, but now decryption has failed), or
            // 2. password provided in this decryption invocation failed to decrypt the ciphertext (password is
            //    incorrect, presumably)
            //
            // In the first case, we clear the cache entry, and in either case we invoke the `decryptionErrorCb`
            // (defaults to `alert` + `throw`, but can be passed a string like "MyApp.myDecryptionErrorCb").
            console.log(`Caught DecryptionError: ${err}`)
            if (cacheHit) {
                console.log(`Clearing cache key ${localStorageKey} after unsuccessful decryption of cached decryptionKeyHex`)
                localStorage.removeItem(localStorageKey)
            }
            const msg =
                cacheHit
                    ? `Decryption failed: ${err.message} (bad / out of date cache; clearing)`
                    : `Decryption failed: ${err.message} (wrong password?)`
            if (!decryptionErrorCb) {
                decryptionErrorCb = ({ err, cacheHit, } : DecryptionErrorCbArgs) => {
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
}

// Perform+verify decryption, return decrypted source + post-PBKDF2 decryption key (for possible caching)
export function _decrypt(
    { encrypted, pswd, iterations, decryptionKeyHex, }: _Decrypt
): {
    source: string,
    decryptionKey: Uint8Array
} {
    let decryptionKey: Uint8Array
    const nonce = encrypted.slice(SALT_LENGTH, SALT_LENGTH + NONCE_LENGTH)
    const ciphertext = encrypted.slice(SALT_LENGTH + NONCE_LENGTH)
    iterations = iterations || DEFAULT_ITERATIONS
    if (decryptionKeyHex) {
        // If the secret is already known + passed in, we can skip the expensive PBKDF2 step
        decryptionKey = fromHexString(decryptionKeyHex)
    } else {
        console.log(`decrypting: ${iterations} iterations`)
        const saltBuf = encrypted.slice(0, SALT_LENGTH)
        console.log(`salt: ${toHexString(saltBuf)}`)
        // console.log(`  pswd: ${pswd}`)
        const salt = convertUint8ArrayToWordArray(saltBuf)
        console.time('hscrypt:PBKDF2')
        decryptionKey = toUint8Array(CryptoJS.PBKDF2(pswd, salt, {
            hasher: CryptoJS.algo.SHA512,
            keySize: DECRYPTION_KEY_LENGTH / 4,
            iterations: iterations || DEFAULT_ITERATIONS
        }))
        console.timeEnd('hscrypt:PBKDF2')
    }
    console.log(`nonce: ${toHexString(nonce)}`)
    console.log(`decryptionKey: ${toHexString(decryptionKey)}`)
    console.log(`iterations: ${iterations}`)
    const decoder = new Chacha20(decryptionKey, nonce)
    console.time('hscrypt:decrypt')
    const plaintext = new TextDecoder().decode(decoder.decrypt(ciphertext))
    console.timeEnd('hscrypt:decrypt')

    // If decryption was successful, the plaintext will begin with the `SOURCE_PREFIX` magic bytes ("/* hscrypt */ ")
    const prefix = plaintext.substring(0, SOURCE_PREFIX.length)
    if (prefix != SOURCE_PREFIX) {
        throw new DecryptionError(`Invalid prefix: ${prefix}`)
    }
    const source = plaintext.substring(SOURCE_PREFIX.length)
    return { source, decryptionKey }
}
