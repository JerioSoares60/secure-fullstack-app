import { useState, useEffect } from 'react';
import secureAPI, { SecureAPIClient } from '../apiClient.js';
import secureCrypto from './encryptPayload.js';
import './App.css';

function App() {
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const [sessionInfo, setSessionInfo] = useState(null);
  const [messages, setMessages] = useState([]);
  const [userData, setUserData] = useState({
    user_id: '',
    username: '',
    email: ''
  });
  const [messageData, setMessageData] = useState({
    message_id: '',
    sender_id: '',
    recipient_id: '',
    content: ''
  });
  const [testData, setTestData] = useState('');
  const [responseData, setResponseData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Initialize secure connection on component mount
    initializeSecureConnection();
  }, []);

  const initializeSecureConnection = async () => {
    try {
      setConnectionStatus('connecting');
      setError(null);
      
      // Perform handshake
      await secureAPI.performHandshake();
      
      // Get session info
      const info = secureAPI.getSessionInfo();
      setSessionInfo(info);
      setConnectionStatus('connected');
      
      addMessage('🔐 Secure connection established', 'success');
    } catch (err) {
      setConnectionStatus('error');
      setError(err.message);
      addMessage(`❌ Connection failed: ${err.message}`, 'error');
    }
  };

  const addMessage = (text, type = 'info') => {
    const newMessage = {
      id: Date.now(),
      text,
      type,
      timestamp: new Date().toLocaleTimeString()
    };
    setMessages(prev => [newMessage, ...prev.slice(0, 9)]); // Keep last 10 messages
  };

  const handleSecureDataTest = async () => {
    try {
      setError(null);
      addMessage('📤 Sending secure data...', 'info');
      
      const data = {
        message: testData || 'Hello from secure client!',
        timestamp: new Date().toISOString(),
        random_value: Math.random()
      };
      
      const response = await secureAPI.sendSecureData(data);
      setResponseData(response.data);
      addMessage('✅ Secure data sent successfully', 'success');
    } catch (err) {
      setError(err.message);
      addMessage(`❌ Secure data failed: ${err.message}`, 'error');
    }
  };

  const handleUserDataTest = async () => {
    try {
      setError(null);
      addMessage('👤 Sending user data...', 'info');
      
      const data = {
        user_id: userData.user_id || `user_${Date.now()}`,
        username: userData.username || 'testuser',
        email: userData.email || 'test@example.com',
        data: {
          preferences: { theme: 'dark', language: 'en' },
          metadata: { created_at: new Date().toISOString() }
        }
      };
      
      const response = await secureAPI.sendUserData(data);
      setResponseData(response.data);
      addMessage('✅ User data sent successfully', 'success');
    } catch (err) {
      setError(err.message);
      addMessage(`❌ User data failed: ${err.message}`, 'error');
    }
  };

  const handleMessageTest = async () => {
    try {
      setError(null);
      addMessage('💬 Sending secure message...', 'info');
      
      const data = {
        message_id: messageData.message_id || `msg_${Date.now()}`,
        sender_id: messageData.sender_id || 'client_001',
        recipient_id: messageData.recipient_id || 'server_001',
        content: messageData.content || 'This is a secure message!',
        timestamp: new Date().toISOString()
      };
      
      const response = await secureAPI.sendMessage(data);
      setResponseData(response.data);
      addMessage('✅ Secure message sent successfully', 'success');
    } catch (err) {
      setError(err.message);
      addMessage(`❌ Message failed: ${err.message}`, 'error');
    }
  };

  const handleHealthCheck = async () => {
    try {
      setError(null);
      addMessage('🏥 Checking server health...', 'info');
      
      const response = await secureAPI.healthCheck();
      setResponseData(response.data);
      addMessage('✅ Health check successful', 'success');
    } catch (err) {
      setError(err.message);
      addMessage(`❌ Health check failed: ${err.message}`, 'error');
    }
  };

  const handleResetSession = () => {
    secureAPI.resetSession();
    setConnectionStatus('disconnected');
    setSessionInfo(null);
    setResponseData(null);
    setError(null);
    addMessage('🔄 Session reset', 'info');
  };

  const handleLegacyTest = async () => {
    try {
      setError(null);
      addMessage('🔄 Testing legacy endpoint...', 'info');
      
      const data = {
        message: 'Legacy test message',
        timestamp: new Date().toISOString()
      };
      
      const response = await secureAPI.sendLegacyData(data);
      setResponseData(response.data);
      addMessage('✅ Legacy test successful', 'success');
    } catch (err) {
      setError(err.message);
      addMessage(`❌ Legacy test failed: ${err.message}`, 'error');
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>🔐 Secure Fullstack App</h1>
        <p> E2EE with AES-256-GCM + ECC</p>
        
        <div className="status-indicator">
          <span className={`status ${connectionStatus}`}>
            {connectionStatus === 'connected' && '🟢 Connected'}
            {connectionStatus === 'connecting' && '🟡 Connecting...'}
            {connectionStatus === 'disconnected' && '🔴 Disconnected'}
            {connectionStatus === 'error' && '🔴 Error'}
          </span>
        </div>
      </header>

      <main className="App-main">
        <div className="grid-container">
          {/* Connection Panel */}
          <div className="panel">
            <h2>🔗 Connection</h2>
            <div className="connection-info">
              {sessionInfo && (
                <div>
                  <p><strong>Client ID:</strong> {sessionInfo.cryptoInfo?.clientId}</p>
                  <p><strong>Session ID:</strong> {sessionInfo.sessionId}</p>
                  <p><strong>Handshake:</strong> {sessionInfo.isHandshakeComplete ? '✅ Complete' : '❌ Pending'}</p>
                  <p><strong>Keys:</strong> {sessionInfo.cryptoInfo?.hasKeys ? '✅ Generated' : '❌ Missing'}</p>
                  <p><strong>Session Key:</strong> {sessionInfo.cryptoInfo?.hasSessionKey ? '✅ Active' : '❌ Inactive'}</p>
                </div>
              )}
            </div>
            <div className="button-group">
              <button onClick={initializeSecureConnection} disabled={connectionStatus === 'connecting'}>
                🔄 Reconnect
              </button>
              <button onClick={handleResetSession} className="secondary">
                🔄 Reset Session
              </button>
            </div>
          </div>

          {/* Test Data Panel */}
          <div className="panel">
            <h2>📤 Secure Data Test</h2>
            <textarea
              value={testData}
              onChange={(e) => setTestData(e.target.value)}
              placeholder="Enter test data to send securely..."
              rows={3}
            />
            <button onClick={handleSecureDataTest} disabled={connectionStatus !== 'connected'}>
              📤 Send Secure Data
            </button>
          </div>

          {/* User Data Panel */}
          <div className="panel">
            <h2>👤 User Data Test</h2>
            <div className="form-group">
              <input
                type="text"
                placeholder="User ID"
                value={userData.user_id}
                onChange={(e) => setUserData(prev => ({ ...prev, user_id: e.target.value }))}
              />
              <input
                type="text"
                placeholder="Username"
                value={userData.username}
                onChange={(e) => setUserData(prev => ({ ...prev, username: e.target.value }))}
              />
              <input
                type="email"
                placeholder="Email"
                value={userData.email}
                onChange={(e) => setUserData(prev => ({ ...prev, email: e.target.value }))}
              />
            </div>
            <button onClick={handleUserDataTest} disabled={connectionStatus !== 'connected'}>
              👤 Send User Data
            </button>
          </div>

          {/* Message Panel */}
          <div className="panel">
            <h2>💬 Message Test</h2>
            <div className="form-group">
              <input
                type="text"
                placeholder="Message ID"
                value={messageData.message_id}
                onChange={(e) => setMessageData(prev => ({ ...prev, message_id: e.target.value }))}
              />
              <input
                type="text"
                placeholder="Sender ID"
                value={messageData.sender_id}
                onChange={(e) => setMessageData(prev => ({ ...prev, sender_id: e.target.value }))}
              />
              <input
                type="text"
                placeholder="Recipient ID"
                value={messageData.recipient_id}
                onChange={(e) => setMessageData(prev => ({ ...prev, recipient_id: e.target.value }))}
              />
              <textarea
                placeholder="Message content"
                value={messageData.content}
                onChange={(e) => setMessageData(prev => ({ ...prev, content: e.target.value }))}
                rows={2}
              />
            </div>
            <button onClick={handleMessageTest} disabled={connectionStatus !== 'connected'}>
              💬 Send Message
            </button>
          </div>

          {/* Utility Panel */}
          <div className="panel">
            <h2>🛠️ Utilities</h2>
            <div className="button-group">
              <button onClick={handleHealthCheck} disabled={connectionStatus !== 'connected'}>
                🏥 Health Check
              </button>
              <button onClick={handleLegacyTest} disabled={connectionStatus !== 'connected'}>
                🔄 Legacy Test
              </button>
            </div>
          </div>

          {/* Response Panel */}
          <div className="panel full-width">
            <h2>📥 Server Response</h2>
            {error && (
              <div className="error-message">
                <strong>Error:</strong> {error}
              </div>
            )}
            {responseData && (
              <pre className="response-data">
                {JSON.stringify(responseData, null, 2)}
              </pre>
            )}
          </div>

          {/* Messages Panel */}
          <div className="panel full-width">
            <h2>📋 Activity Log</h2>
            <div className="messages-container">
              {messages.map(msg => (
                <div key={msg.id} className={`message ${msg.type}`}>
                  <span className="timestamp">{msg.timestamp}</span>
                  <span className="text">{msg.text}</span>
                </div>
              ))}
              {messages.length === 0 && (
                <p className="no-messages">No activity yet...</p>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
