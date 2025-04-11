// frontend/keyxfrontend/src/App.js
import React, { useState } from 'react';
import axios from 'axios';

export default function App() {
  const [username, setUsername] = useState('');
  const [file, setFile] = useState(null);
  const [filename, setFilename] = useState('');
  const [downloadUrl, setDownloadUrl] = useState('');
  const [privateKeyFile, setPrivateKeyFile] = useState(null);
  const [message, setMessage] = useState('');

  const api = axios.create({ baseURL: 'http://localhost:7500' });

  // Register User and download keys
  const handleRegisterUser = async () => {
    try {
      const form = new FormData();
      form.append('username', username);
      const res = await api.post('/register_user', form);

      const { public_key, private_key } = res.data;

      downloadKey(public_key, `${username}_public.pem`);
      downloadKey(private_key, `${username}_private.pem`);

      setMessage('Keys generated and downloaded.');
    } catch (err) {
      console.error(err);
      setMessage('Error registering user');
    }
  };

  // Download keys (public/private) as .pem files
  const downloadKey = (content, filename) => {
    const blob = new Blob([content], { type: 'application/x-pem-file' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
  };

  // Revoke User's access
  const handleRevokeUser = async () => {
    try {
      const form = new FormData();
      form.append('username', username);
      const res = await api.post('/delete_user', form);
      setMessage(res.data.message);
    } catch (err) {
      setMessage('Error revoking user');
    }
  };

  // Handle file upload and encryption
    const handleUpload = async () => {
        if (!file || !username || !filename) return;

        try {
            const form = new FormData();
            form.append('file', file);
            form.append('username', username);
            form.append('filename', filename);

            const res = await api.post('/upload', form);
            setMessage('File uploaded and encrypted');
        } catch (err) {
            console.error(err);
            setMessage('Upload failed');
        }
    };



  // Handle file download and decryption
  const handleDownload = async () => {
    if (!privateKeyFile || !filename || !username) {
      setMessage('Please upload a private key file, enter file name, and username');
      return;
    }

    try {
      const form = new FormData();
      form.append('filename', filename);
      form.append('private_key_file', privateKeyFile);
      form.append('username', username);

      const res = await api.post('/download', form, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      setDownloadUrl(url);
      setMessage('File decrypted and ready for download');
    } catch (err) {
      console.error(err);
      setMessage('Decryption failed');
    }
  };

  return (
    <div className="p-4 space-y-4">
      <h1 className="text-xl font-bold">Secure File Share</h1>

      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        className="border p-2 w-full"
      />
      <br />
      <div className="flex space-x-2">
        <button onClick={handleRegisterUser} className="bg-blue-500 text-white p-2 rounded">Register User</button>
        <br />
        <button onClick={handleRevokeUser} className="bg-red-500 text-white p-2 rounded">Revoke Access</button>
      </div>
      <br />
      <input type="file" onChange={(e) => setFile(e.target.files[0])} className="w-full" /><br />
      <input
        type="text"
        placeholder="Filename (e.g., mydoc.txt)"
        value={filename}
        onChange={(e) => setFilename(e.target.value)}
        className="border p-2 w-full"
      /><br />
      <button onClick={handleUpload} className="bg-purple-500 text-white p-2 rounded w-full">Encrypt & Upload</button>
      <br />
      <input type="file" onChange={(e) => setPrivateKeyFile(e.target.files[0])} className="w-full" />
      <button onClick={handleDownload} className="bg-yellow-500 text-black p-2 rounded w-full">Download & Decrypt</button>
      <br />
      {downloadUrl && (
        <a href={downloadUrl} download className="block mt-2 text-blue-600 underline">Click here to download</a>
      )}
      <br />
      {message && <div className="mt-2 text-gray-700">{message}</div>}
    </div>
  );
}
