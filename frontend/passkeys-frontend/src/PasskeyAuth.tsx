import React, { useState } from 'react';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

const PasskeyAuth = () => {
  const [username, setUsername] = useState('');
  const [message, setMessage] = useState('');

  const BACKEND_URL = "http://localhost:4000";

  const handleRegister = async () => {
    try {
      // Get registration options from server
      const optionsRes = await fetch(`${BACKEND_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      const options = await optionsRes.json();

      // Start the registration process
      const regResult = await startRegistration(options);

      // Send the result to the server for verification
      const verificationRes = await fetch(`${BACKEND_URL}/register/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, response: regResult }),
      });
      const verificationResult = await verificationRes.json();

      if (verificationResult.verified) {
        setMessage('Registration successful!');
      } else {
        setMessage('Registration failed. Please try again.');
      }
    } catch (error) {
      console.error(error);
      setMessage('An error occurred during registration.');
    }
  };

  const handleLogin = async () => {
    try {
      // Get authentication options from server
      const optionsRes = await fetch(`${BACKEND_URL}/authenticate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      const options = await optionsRes.json();

      // Start the authentication process
      const authResult = await startAuthentication(options);

      // Send the result to the server for verification
      const verificationRes = await fetch(`${BACKEND_URL}/authenticate/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, response: authResult }),
      });
      const verificationResult = await verificationRes.json();

      if (verificationResult.verified) {
        setMessage('Authentication successful!');
      } else {
        setMessage(verificationResult.message || 'Authentication failed. Please try again.');
      }
    } catch (error) {
      console.log(error);
      setMessage(error.message || 'An error occurred during authentication.');
    }
  };

  return (
    <div>
      <h1>Passkey Authentication</h1>
      <input
        type="text"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        placeholder="Enter username"
      />
      <button onClick={handleRegister}>Register</button>
      <button onClick={handleLogin}>Login</button>
      {message && <p>{message}</p>}
    </div>
  );
};

export default PasskeyAuth;