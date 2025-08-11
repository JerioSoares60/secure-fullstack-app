import axios from 'axios';
import secureCrypto from './src/encryptPayload.js';

class SecureAPIClient {
    constructor(baseURL) {
        this.baseURL = baseURL;
        this.isHandshakeComplete = false;
        this.sessionId = null;
        
        // Create axios instance
        this.api = axios.create({ 
            baseURL: this.baseURL,
            timeout: 30000,
            headers: {
                'Content-Type': 'application/json',
            }
        });

        // Setup interceptors
        this.setupInterceptors();
    }

    setupInterceptors() {
        // Request interceptor for automatic encryption
        this.api.interceptors.request.use(async (config) => {
            // Ensure handshake is completed
            if (!this.isHandshakeComplete) {
                await this.performHandshake();
            }

            // Add session ID to headers
            if (this.sessionId) {
                config.headers['X-Session-ID'] = this.sessionId;
            }

            // Encrypt request data if present
            if (config.data) {
                try {
                    const encryptedData = await secureCrypto.encryptPayload(config.data);
                    config.data = {
                        encrypted_data: encryptedData,
                        client_id: secureCrypto.clientId
                    };
                } catch (error) {
                    console.error('Encryption failed:', error);
                    throw error;
                }
            }

            return config;
        }, (error) => {
            return Promise.reject(error);
        });

        // Response interceptor for automatic decryption
        this.api.interceptors.response.use(async (response) => {
            // Decrypt response data if it's encrypted
            if (response.data && response.data.encrypted_data) {
                try {
                    const decryptedData = await secureCrypto.decryptResponse(response.data.encrypted_data);
                    response.data = decryptedData;
                } catch (error) {
                    console.error('Decryption failed:', error);
                    throw error;
                }
            }

            return response;
        }, async (error) => {
            // Handle session expiration
            if (error.response && error.response.status === 401) {
                console.log('Session expired, performing new handshake...');
                this.isHandshakeComplete = false;
                this.sessionId = null;
                
                // Retry the request with new handshake
                try {
                    await this.performHandshake();
                    // Retry the original request
                    const originalRequest = error.config;
                    originalRequest.headers['X-Session-ID'] = this.sessionId;
                    return this.api(originalRequest);
                } catch (handshakeError) {
                    console.error('Handshake retry failed:', handshakeError);
                }
            }
            
            return Promise.reject(error);
        });
    }

    async performHandshake() {
        try {
            console.log('🔐 Performing secure handshake...');
            const handshakeResponse = await secureCrypto.performHandshake(this.baseURL);
            this.sessionId = handshakeResponse.session_id;
            this.isHandshakeComplete = true;
            console.log('✅ Handshake completed successfully');
            return handshakeResponse;
        } catch (error) {
            console.error('❌ Handshake failed:', error);
            throw error;
        }
    }

    // Secure API methods
    async sendSecureData(data) {
        return this.api.post('/api/v1/secure/data', data);
    }

    async sendUserData(userData) {
        return this.api.post('/api/v1/secure/user', userData);
    }

    async sendMessage(messageData) {
        return this.api.post('/api/v1/secure/message', messageData);
    }

    async getSessionInfo(sessionId) {
        return this.api.get(`/api/v1/session/${sessionId}`);
    }

    async invalidateSession(sessionId) {
        return this.api.delete(`/api/v1/session/${sessionId}`);
    }

    async healthCheck() {
        return this.api.get('/api/v1/health');
    }

    // Legacy endpoint for backward compatibility
    async sendLegacyData(data) {
        try {
            // Use legacy encryption
            const legacyEncrypted = await this.legacyEncrypt(data);
            return this.api.post('/api/v1/secure-endpoint', { payload: legacyEncrypted });
        } catch (error) {
            console.error('Legacy encryption failed:', error);
            throw error;
        }
    }

    async legacyEncrypt(data) {
        // Legacy encryption using environment variable
        const encoded = new TextEncoder().encode(JSON.stringify(data));
        const key = await this.getLegacyKey();

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            encoded
        );

        const combined = new Uint8Array([...iv, ...new Uint8Array(ciphertext)]);
        return btoa(String.fromCharCode(...combined));
    }

    async getLegacyKey() {
        const rawKey = new TextEncoder().encode(import.meta.env.VITE_ENCRYPTION_KEY);
        return await crypto.subtle.importKey(
            "raw",
            rawKey,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );
    }

    // Utility methods
    getSessionInfo() {
        return {
            isHandshakeComplete: this.isHandshakeComplete,
            sessionId: this.sessionId,
            cryptoInfo: secureCrypto.getSessionInfo()
        };
    }

    resetSession() {
        this.isHandshakeComplete = false;
        this.sessionId = null;
        secureCrypto.sessionId = null;
        secureCrypto.sessionKey = null;
        console.log('🔄 Session reset');
    }
}

// Create default instance
const defaultBaseURL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
const secureAPI = new SecureAPIClient(defaultBaseURL);

// Export both the class and default instance
export default secureAPI;
export { SecureAPIClient };
