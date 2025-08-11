// Enhanced encryption utilities with ECC key exchange
class SecureCryptoClient {
    constructor() {
        this.clientKeys = null;
        this.serverPublicKey = null;
        this.sessionId = null;
        this.sessionKey = null;
        this.clientId = this.generateClientId();
    }

    generateClientId() {
        return 'client_' + crypto.getRandomValues(new Uint8Array(16))
            .reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
    }

    async generateECCKeyPair() {
        try {
            // Generate ECC key pair using P-256 curve
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true,
                ["deriveKey", "deriveBits"]
            );
            
            this.clientKeys = keyPair;
            return keyPair;
        } catch (error) {
            console.error('Failed to generate ECC key pair:', error);
            throw error;
        }
    }

    async exportPublicKey() {
        if (!this.clientKeys) {
            throw new Error('Client keys not generated');
        }

        const exported = await crypto.subtle.exportKey(
            "spki",
            this.clientKeys.publicKey
        );
        
        return btoa(String.fromCharCode(...new Uint8Array(exported)));
    }

    async importServerPublicKey(serverPublicKeyB64) {
        try {
            if (!serverPublicKeyB64 || typeof serverPublicKeyB64 !== 'string') {
                throw new Error('Invalid server public key: must be a non-empty string');
            }
            
            const serverKeyBytes = Uint8Array.from(atob(serverPublicKeyB64), c => c.charCodeAt(0));
            this.serverPublicKey = await crypto.subtle.importKey(
                "spki",
                serverKeyBytes,
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true,
                []
            );
        } catch (error) {
            console.error('Failed to import server public key:', error);
            throw error;
        }
    }

    async deriveSessionKey() {
        if (!this.clientKeys || !this.serverPublicKey) {
            throw new Error('Both client and server keys required');
        }

        try {
            // Perform ECDH key exchange
            const sharedSecret = await crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: this.serverPublicKey
                },
                this.clientKeys.privateKey,
                256
            );

            // Derive session key using HKDF
            const sessionKey = await crypto.subtle.deriveKey(
                {
                    name: "HKDF",
                    salt: new TextEncoder().encode("secure_fullstack_app_salt"),
                    info: new TextEncoder().encode(this.sessionId),
                    hash: "SHA-256"
                },
                sharedSecret,
                {
                    name: "AES-GCM",
                    length: 256
                },
                true,
                ["encrypt", "decrypt"]
            );

            this.sessionKey = sessionKey;
            return sessionKey;
        } catch (error) {
            console.error('Failed to derive session key:', error);
            throw error;
        }
    }

    async performHandshake(apiBaseUrl) {
        try {
            // Generate client key pair if not exists
            if (!this.clientKeys) {
                await this.generateECCKeyPair();
            }

            // Export client public key
            const clientPublicKey = await this.exportPublicKey();

            // Perform handshake with server
            const response = await fetch(`${apiBaseUrl}/api/v1/handshake`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    client_public_key: clientPublicKey
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Handshake failed: ${response.status} - ${errorText}`);
            }

            const handshakeResponse = await response.json();
            
            // Validate response structure
            if (!handshakeResponse.session_id || !handshakeResponse.server_public_key) {
                throw new Error('Invalid handshake response: missing session_id or server_public_key');
            }
            
            // Store session information
            this.sessionId = handshakeResponse.session_id;
            
            // Import server public key
            await this.importServerPublicKey(handshakeResponse.server_public_key);
            
            // Derive session key
            await this.deriveSessionKey();

            console.log('🔐 Handshake completed successfully');
            return handshakeResponse;
        } catch (error) {
            console.error('Handshake failed:', error);
            throw error;
        }
    }

    async encryptPayload(data) {
        if (!this.sessionKey || !this.sessionId) {
            throw new Error('Session not established. Perform handshake first.');
        }

        try {
            // Generate random IV (12 bytes for GCM)
            const iv = crypto.getRandomValues(new Uint8Array(12));
            // Serialize data to JSON
            const jsonData = JSON.stringify(data);
            const encodedData = new TextEncoder().encode(jsonData);
            // Encrypt data using AES-GCM
            const encryptedData = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                this.sessionKey,
                encodedData
            );
            // Create signature using HMAC
            const signature = await this.createSignature(iv, encryptedData);
            return {
                payload: btoa(String.fromCharCode(...new Uint8Array(encryptedData))),
                iv: btoa(String.fromCharCode(...iv)),
                tag: btoa(String.fromCharCode(...new Uint8Array(encryptedData).slice(-16))),
                signature: signature
            };
        } catch (error) {
            console.error('Encryption failed:', error);
            throw error;
        }
    }

    async createSignature(iv, encryptedData) {
        try {
            // Create HMAC key from session key
            const hmacKey = await crypto.subtle.importKey(
                "raw",
                await crypto.subtle.exportKey("raw", this.sessionKey),
                {
                    name: "HMAC",
                    hash: "SHA-256"
                },
                false,
                ["sign"]
            );

            // Create signature
            const signature = await crypto.subtle.sign(
                "HMAC",
                hmacKey,
                new Uint8Array([...iv, ...new Uint8Array(encryptedData)])
            );

            return btoa(String.fromCharCode(...new Uint8Array(signature)));
        } catch (error) {
            console.error('Signature creation failed:', error);
            throw error;
        }
    }

    async decryptResponse(encryptedData) {
        if (!this.sessionKey) {
            throw new Error('Session key not available');
        }

        try {
            // Decode base64 components
            const ciphertext = Uint8Array.from(atob(encryptedData.payload), c => c.charCodeAt(0));
            const iv = Uint8Array.from(atob(encryptedData.iv), c => c.charCodeAt(0));
            const tag = Uint8Array.from(atob(encryptedData.tag), c => c.charCodeAt(0));
            const signature = Uint8Array.from(atob(encryptedData.signature), c => c.charCodeAt(0));

            // Verify signature
            const isValid = await this.verifySignature(iv, ciphertext, signature);
            if (!isValid) {
                throw new Error('Invalid signature - data integrity check failed');
            }

            // Combine ciphertext and tag for decryption
            const encryptedWithTag = new Uint8Array([...ciphertext, ...tag]);

            // Decrypt data
            const decryptedData = await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                this.sessionKey,
                encryptedWithTag
            );

            // Parse JSON
            const jsonString = new TextDecoder().decode(decryptedData);
            return JSON.parse(jsonString);
        } catch (error) {
            console.error('Decryption failed:', error);
            throw error;
        }
    }

    async verifySignature(iv, ciphertext, signature) {
        try {
            // Create HMAC key from session key
            const hmacKey = await crypto.subtle.importKey(
    "raw",
                await crypto.subtle.exportKey("raw", this.sessionKey),
                {
                    name: "HMAC",
                    hash: "SHA-256"
                },
    false,
                ["verify"]
            );

            // Verify signature
            return await crypto.subtle.verify(
                "HMAC",
                hmacKey,
                signature,
                new Uint8Array([...iv, ...ciphertext])
            );
        } catch (error) {
            console.error('Signature verification failed:', error);
            return false;
        }
    }

    getSessionInfo() {
        return {
            clientId: this.clientId,
            sessionId: this.sessionId,
            hasKeys: !!this.clientKeys,
            hasServerKey: !!this.serverPublicKey,
            hasSessionKey: !!this.sessionKey
        };
    }
}

// Create global instance
const secureCrypto = new SecureCryptoClient();

// Export functions for backward compatibility
export async function encryptPayload(data) {
    return await secureCrypto.encryptPayload(data);
}

export async function decryptResponse(encryptedData) {
    return await secureCrypto.decryptResponse(encryptedData);
}

// Export the main class
export default secureCrypto;
