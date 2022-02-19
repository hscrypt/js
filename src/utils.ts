// Cipher params
export const SECRET_KEY_LENGTH = 32
export const DEFAULT_ITERATIONS = 10_000
export const SALT_LENGTH = 32
export const NONCE_LENGTH = 12

// Prepend this to source before encrypting, verify+remove during decryption, to check whether decryption succeeded
export const SOURCE_PREFIX = '/* hscrypt */ '


export function fromHexString(hexString: string): Uint8Array {
    return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

export function toHexString(bytes: Uint8Array): string {
    return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}
