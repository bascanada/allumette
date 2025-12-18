// src/lib/crypto-utils.js

/**
 * Derives a CryptoKey for AES-GCM from a raw key material (e.g., private key bytes).
 * We use PBKDF2 to expand entropy if needed, or just import if high entropy.
 * Assuming input is already high entropy (private key), we can import directly or hash it.
 * To be safe and standard, we'll SHA-256 the input to get a 32-byte key.
 */
export async function deriveEncryptionKey(secretBytes) {
    const hash = await crypto.subtle.digest('SHA-256', secretBytes);
    return crypto.subtle.importKey(
        'raw',
        hash,
        { name: 'AES-GCM' },
        false, // not extractable
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypts a JSON object/value.
 * Returns { iv: string (base64), ciphertext: string (base64) }
 */
export async function encryptData(data, cryptoKey) {
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for AES-GCM

    const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        encoded
    );

    return {
        iv: arrayBufferToBase64(iv),
        ciphertext: arrayBufferToBase64(ciphertextBuffer)
    };
}

/**
 * Decrypts data.
 * Expects { iv: string (base64), ciphertext: string (base64) }
 * Returns the parsed JSON object.
 */
export async function decryptData(encryptedObj, cryptoKey) {
    const iv = base64ToArrayBuffer(encryptedObj.iv);
    const ciphertext = base64ToArrayBuffer(encryptedObj.ciphertext);

    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        ciphertext
    );

    const decoded = new TextDecoder().decode(decryptedBuffer);
    return JSON.parse(decoded);
}

// Helpers
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary_string = atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}
