// Enhanced decryption utilities with signature verification
import secureCrypto from './encrypt.js';

export async function decryptResponse(responseData) {
    try {
        if (!secureCrypto.sessionKeys) {
            throw new Error('Session not established. Perform handshake first.');
        }

        // Handle both nested and flat response formats
        const encryptedData = responseData.encrypted_data || responseData;
        
        // Validate required fields
        if (!encryptedData.payload || !encryptedData.iv || 
            !encryptedData.tag || !encryptedData.signature) {
            throw new Error('Invalid encrypted data format');
        }

        // Decode base64 components
        const ciphertext = Uint8Array.from(atob(encryptedData.payload), c => c.charCodeAt(0));
        const iv = Uint8Array.from(atob(encryptedData.iv), c => c.charCodeAt(0));
        const tag = Uint8Array.from(atob(encryptedData.tag), c => c.charCodeAt(0));
        const signature = Uint8Array.from(atob(encryptedData.signature), c => c.charCodeAt(0));

        // Verify signature first (includes IV + ciphertext + tag)
        const isValid = await secureCrypto.verifySignature(iv, ciphertext, tag, signature);
        if (!isValid) {
            throw new Error('Invalid HMAC signature - possible tampering detected');
        }

        // Combine ciphertext and tag for decryption
        const combined = new Uint8Array([...ciphertext, ...tag]);
        
        // Decrypt using AES-GCM
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            secureCrypto.sessionKeys.aesKey,
            combined
        );

        // Parse and return decrypted data
        return JSON.parse(new TextDecoder().decode(decrypted));
    } catch (error) {
        console.error('Decryption failed:', error);
        throw new Error(`Decryption failed: ${error.message}`);
    }
}

// Remove legacy decryption function as it's not compatible with the new E2EE system
// Export the crypto client for direct access
export { secureCrypto };