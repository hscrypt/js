import CryptoJS from "crypto-js";
import { Chacha20 } from "ts-chacha20";

function checkStatus(response: Response) {
    if (!response.ok) {
        throw new Error(`HTTP ${response.status} - ${response.statusText}`);
    }
    return response;
}

const SECRET_KEY_LENGTH = 32
const DEFAULT_ITERATIONS = 10_000
const SALT_LENGTH = 32
const NONCE_LENGTH = 12

export function inject(src: string, pswd: string, iterations: number = DEFAULT_ITERATIONS) {
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
            const source = decrypt({ encrypted, pswd, iterations, })
            //console.log(`hscrypt: injecting ${source}`)
            const script = document.createElement('script')
            script.setAttribute("type", "text/javascript")
            script.innerHTML = source
            document.body.appendChild(script)
        })
}

/* Converts a cryptjs WordArray to native Uint8Array */
function CryptJsWordArrayToUint8Array(wordArray: CryptoJS.lib.WordArray) {
    const l = wordArray.sigBytes;
    const words = wordArray.words;
    const result = new Uint8Array(l);
    var i=0 /*dst*/, j=0 /*src*/;
    while(true) {
        // here i is a multiple of 4
        if (i==l)
            break;
        var w = words[j++];
        result[i++] = (w & 0xff000000) >>> 24;
        if (i==l)
            break;
        result[i++] = (w & 0x00ff0000) >>> 16;
        if (i==l)
            break;
        result[i++] = (w & 0x0000ff00) >>> 8;
        if (i==l)
            break;
        result[i++] = (w & 0x000000ff);
    }
    return result;
}

// assumes wordArray is Big-Endian (because it comes from CryptoJS which is all BE)
// From: https://gist.github.com/creationix/07856504cf4d5cede5f9#file-encode-js
function convertWordArrayToUint8Array(wordArray: CryptoJS.lib.WordArray) {
    var len = wordArray.words.length,
        u8_array = new Uint8Array(len << 2),
        offset = 0, word, i
    ;
    for (i=0; i<len; i++) {
        word = wordArray.words[i];
        u8_array[offset++] = word >> 24;
        u8_array[offset++] = (word >> 16) & 0xff;
        u8_array[offset++] = (word >> 8) & 0xff;
        u8_array[offset++] = word & 0xff;
    }
    return u8_array;
}

// create a wordArray that is Big-Endian (because it's used with CryptoJS which is all BE)
// From: https://gist.github.com/creationix/07856504cf4d5cede5f9#file-encode-js
function convertUint8ArrayToWordArray(u8Array: Uint8Array): CryptoJS.lib.WordArray {
    var words = [], i = 0, len = u8Array.length;

    while (i < len) {
        words.push(
            (u8Array[i++] << 24) |
            (u8Array[i++] << 16) |
            (u8Array[i++] << 8)  |
            (u8Array[i++])
        );
    }

    return CryptoJS.lib.WordArray.create(
        words,
        words.length * 4,
    );
}

export function encrypt({ source, pswd, iterations, }: {
    source: string | Buffer,
    pswd: string,
    iterations?: number
}): Uint8Array {
    const salt = CryptoJS.lib.WordArray.random(SALT_LENGTH)
    const saltBuf = CryptJsWordArrayToUint8Array(salt)
    const secret = CryptJsWordArrayToUint8Array(CryptoJS.PBKDF2(pswd, salt, { hasher: CryptoJS.algo.SHA512, keySize: SECRET_KEY_LENGTH / 4, iterations: iterations || DEFAULT_ITERATIONS }))
    const nonce = CryptJsWordArrayToUint8Array(CryptoJS.lib.WordArray.random(NONCE_LENGTH))

    const encoder = new Chacha20(secret, nonce)

    const input = (typeof source === 'string') ? new TextEncoder().encode(source) : source
    const ciphertext = encoder.encrypt(input)

    const encrypted = new Uint8Array(saltBuf.length + nonce.length + ciphertext.length)
    encrypted.set(saltBuf, 0)
    encrypted.set(nonce, saltBuf.length)
    encrypted.set(ciphertext, saltBuf.length + nonce.length)

    return encrypted
}

export function decrypt({ encrypted, pswd, iterations, }: {
    encrypted: Uint8Array,
    pswd: string,
    iterations?: number,
}): string {
    console.log(`decrypting: ${iterations} iterations`)
    const salt = convertUint8ArrayToWordArray(encrypted.slice(0, SALT_LENGTH))
    const nonce = encrypted.slice(SALT_LENGTH, SALT_LENGTH + NONCE_LENGTH)
    const ciphertext = encrypted.slice(SALT_LENGTH + NONCE_LENGTH)
    const secret = CryptJsWordArrayToUint8Array(CryptoJS.PBKDF2(pswd, salt, { hasher: CryptoJS.algo.SHA512, keySize: SECRET_KEY_LENGTH / 4, iterations: iterations || DEFAULT_ITERATIONS }))

    const decoder = new Chacha20(secret, nonce)
    const source = new TextDecoder().decode(decoder.decrypt(ciphertext))

    return source
}
