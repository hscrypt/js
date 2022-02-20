export const LOCALSTORAGE_PREFIX = "hscrypt.secret:"

export function getLocalStorageKey() {
    const path = window.location.pathname
    return `${LOCALSTORAGE_PREFIX}${path}`
}

export function getCachedDecryptionKey() {
    const localStorageKey = getLocalStorageKey()
    return localStorage.getItem(localStorageKey)
}

export function clearCachedDecryptionKey() {
    const localStorageKey = getLocalStorageKey()
    return localStorage.removeItem(localStorageKey)
}
