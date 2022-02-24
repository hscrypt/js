// Name of a global config object stored on `window`
export const HSCRYPT_CONFIG_VAR = 'HSCRYPT_CONFIG'

// Cipher params
export const DECRYPTION_KEY_LENGTH = 32
export const DEFAULT_ITERATIONS = 20_000
export const SALT_LENGTH = 32
export const NONCE_LENGTH = 12

// Prepend this to source before encrypting, verify+remove during decryption, to check whether decryption succeeded
export const SOURCE_PREFIX = '/* hscrypt */ '
export const SOURCE_PREFIX_ARRAY = new TextEncoder().encode(SOURCE_PREFIX)

export type Source = string | Uint8Array

export function fromHexString(hexString: string): Uint8Array {
    return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

export function toHexString(bytes: Uint8Array): string {
    return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}
