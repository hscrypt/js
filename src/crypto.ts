import CryptoJS from "crypto-js";

/* Converts a cryptojs WordArray to native Uint8Array */
export function toUint8Array(wordArray: CryptoJS.lib.WordArray) {
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
// function convertWordArrayToUint8Array(wordArray: CryptoJS.lib.WordArray) {
//     var len = wordArray.words.length,
//         u8_array = new Uint8Array(len << 2),
//         offset = 0, word, i
//     ;
//     for (i=0; i<len; i++) {
//         word = wordArray.words[i];
//         u8_array[offset++] = word >> 24;
//         u8_array[offset++] = (word >> 16) & 0xff;
//         u8_array[offset++] = (word >> 8) & 0xff;
//         u8_array[offset++] = word & 0xff;
//     }
//     return u8_array;
// }

// create a wordArray that is Big-Endian (because it's used with CryptoJS which is all BE)
// From: https://gist.github.com/creationix/07856504cf4d5cede5f9#file-encode-js
export function convertUint8ArrayToWordArray(u8Array: Uint8Array): CryptoJS.lib.WordArray {
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
