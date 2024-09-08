import React, { useState } from 'react';
import { ethers } from 'ethers';
import { keccak256, arrayify } from 'ethers/lib/utils';
import { ExternalProvider } from '@ethersproject/providers';

declare global {
  interface Window {
    ethereum?: ExternalProvider;
  }
}

const App: React.FC = () => {
  const [wallet, setWallet] = useState<ethers.Signer | null>(null);
  const [userAddress, setUserAddress] = useState<string>('');
  const [saltKey, setSaltKey] = useState<string>(''); // Alterado para SaltKey
  const [privateKey, setPrivateKey] = useState<string>('');
  const [masterKey, setMasterKey] = useState<string>('');
  const [jsonInput, setJsonInput] = useState<string>('');
  const [bitMask, setBitMask] = useState<string>('111');
  const [encryptedData, setEncryptedData] = useState<string>('');
  const [encryptionSalt, setEncryptionSalt] = useState<string>('');
  const [decryptedData, setDecryptedData] = useState<string>('');

  const connectWallet = async () => {
    if (!window.ethereum) {
      alert('Por favor, instale o MetaMask para continuar.');
      return;
    }
    try {
      const provider = new ethers.providers.Web3Provider(window.ethereum);
      await provider.send('eth_requestAccounts', []);
      const signer = provider.getSigner();
      const address = await signer.getAddress();
      setWallet(signer);
      setUserAddress(address);
      alert(`Carteira conectada: ${address}`);
    } catch (error) {
      console.error('Erro ao conectar carteira:', error);
    }
  };

  // Função para gerar a MasterKey usando apenas saltKey e privateKey
  const handleGenerateMasterKey = () => {
    if (!saltKey || !privateKey) {
      alert('Por favor, insira o saltKey e a chave privada.');
      return;
    }

    // Gera a MasterKey com base no saltKey e privateKey
    const masterKeyBytes = ethers.utils.keccak256(
      ethers.utils.toUtf8Bytes(saltKey + privateKey)
    );
    setMasterKey(masterKeyBytes);
    alert('MasterKey gerada com sucesso!');
  };

  const handleEncryptData = async () => {
    if (!wallet) {
      alert('Por favor, conecte sua carteira primeiro.');
      return;
    }
    if (!jsonInput || !bitMask || !masterKey) {
      alert('Por favor, insira os dados JSON, bitmask e gere a chave mestre.');
      return;
    }
    try {
      const parsedJson = JSON.parse(jsonInput);
      const jsonString = JSON.stringify(parsedJson);
      const messageHash = keccak256(ethers.utils.toUtf8Bytes(jsonString));
      const signature = await wallet.signMessage(arrayify(messageHash));
      console.log(signature);

      const response = await fetch('http://localhost:8080/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonData: parsedJson,
          signature,
          masterKey,
          bitMask,
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setEncryptedData(data.encryptedData);
        setEncryptionSalt(data.salt);
        alert('Dados criptografados com sucesso!');
      } else {
        console.error('Erro ao criptografar dados:', data.error);
        alert(`Erro ao criptografar dados: ${data.error}`);
      }
    } catch (error) {
      console.error('Erro ao criptografar dados:', error);
      alert('Erro ao criptografar dados. Verifique o console para mais detalhes.');
    }
  };

  const handleDecryptWithMasterKey = async () => {
    if (!wallet || !masterKey || !encryptedData) {
      alert('Por favor, insira todos os dados.');
      return;
    }

    // Adicionar o prefixo Ethereum à mensagem antes de assinar
    const message = `\x19Ethereum Signed Message:\n${encryptedData.length}${encryptedData}`;
    const messageHash = keccak256(ethers.utils.toUtf8Bytes(message));  // Gerar o hash da mensagem prefixada
    const signature = await wallet.signMessage(arrayify(messageHash));  // Assinar a mensagem hash
    const userAddress = await wallet.getAddress();

    console.log("encryptedData", encryptedData);
    console.log("Assinatura do usuário:", signature);
    console.log("MessageHash:", messageHash);
    console.log("Endereço do usuário:", userAddress);

    const response = await fetch('http://localhost:8080/decrypt-with-masterkey', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        encryptedData,
        masterKey,
        saltKey, 
        privateKey,
        salt: encryptionSalt,
        bitMask,
        userSignature: signature,
        userAddress,
      }),
    });

    const data = await response.json();

    if (response.ok) {
      setDecryptedData(JSON.stringify(data.decryptedData, null, 2));
      alert('Dados descriptografados com sucesso!');
    } else {
      console.error('Erro ao descriptografar dados:', data.error);
      alert(`Erro ao descriptografar dados: ${data.error}`);
    }
  };

  return (
    <div style={{ padding: '20px' }}>
      <h1>Criptografia e Descriptografia com Ethereum</h1>

      {/* Seção de Conexão da Carteira */}
      <section style={{ marginBottom: '40px' }}>
        <h2>1. Conectar Carteira Ethereum</h2>
        <button onClick={connectWallet} style={{ padding: '10px 20px' }}>
          Conectar Carteira
        </button>
        {userAddress && (
          <p>
            <strong>Carteira conectada:</strong> {userAddress}
          </p>
        )}
      </section>

      {/* Seção de Geração da Chave Mestre */}
      <section style={{ marginBottom: '40px' }}>
        <h2>2. Gerar Chave Mestre</h2>
        <div style={{ marginBottom: '10px' }}>
          <label>Salt Key:</label> {/* Alterado de "Endereço do Contrato" para "Salt Key" */}
          <br />
          <input
            type="text"
            value={saltKey} // Alterado para saltKey
            onChange={(e) => setSaltKey(e.target.value)}
            placeholder="Ex: 0x1234..."
            style={{ width: '100%', padding: '8px' }}
          />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <label>Chave Privada (Senha):</label>
          <br />
          <input
            type="password"
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
            placeholder="Sua chave privada ou senha secreta"
            style={{ width: '100%', padding: '8px' }}
          />
        </div>
        <button onClick={handleGenerateMasterKey} style={{ padding: '10px 20px' }}>
          Gerar Chave Mestre
        </button>
        {masterKey && (
          <p>
            <strong>Chave Mestre Gerada:</strong> {masterKey}
          </p>
        )}
      </section>

      {/* Seção de Criptografia */}
      <section style={{ marginBottom: '40px' }}>
        <h2>3. Assinar e Criptografar Dados</h2>
        <div style={{ marginBottom: '10px' }}>
          <label>Dados JSON:</label>
          <br />
          <textarea
            value={jsonInput}
            onChange={(e) => setJsonInput(e.target.value)}
            placeholder='Ex: {"name": "Alice", "age": 30, "email": "alice@example.com"}'
            rows={6}
            style={{ width: '100%', padding: '8px' }}
          />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <label>Bitmask:</label>
          <br />
          <input
            type="text"
            value={bitMask}
            onChange={(e) => setBitMask(e.target.value)}
            placeholder="Ex: 101 (1 para criptografar, 0 para deixar em claro)"
            style={{ width: '100%', padding: '8px' }}
          />
        </div>
        <button onClick={handleEncryptData} style={{ padding: '10px 20px' }}>
          Assinar e Criptografar
        </button>
        {encryptedData && encryptionSalt && (
          <div style={{ marginTop: '20px' }}>
            <p>
              <strong>Dados Criptografados:</strong> {encryptedData}
            </p>
            <p>
              <strong>Salt:</strong> {encryptionSalt}
            </p>
          </div>
        )}
      </section>

      {/* Seção de Descriptografia */}
      <section style={{ marginBottom: '40px' }}>
        <h2>4. Descriptografar Dados</h2>
        <div style={{ marginBottom: '10px' }}>
          <label>Dados Criptografados:</label>
          <br />
          <textarea
            value={encryptedData}
            onChange={(e) => setEncryptedData(e.target.value)}
            placeholder="Insira os dados criptografados aqui"
            rows={4}
            style={{ width: '100%', padding: '8px' }}
          />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <label>Salt:</label>
          <br />
          <input
            type="text"
            value={encryptionSalt}
            onChange={(e) => setEncryptionSalt(e.target.value)}
            placeholder="Insira o salt correspondente"
            style={{ width: '100%', padding: '8px' }}
          />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <label>Bitmask:</label>
          <br />
          <input
            type="text"
            value={bitMask}
            onChange={(e) => setBitMask(e.target.value)}
            placeholder="Insira a bitmask correspondente"
            style={{ width: '100%', padding: '8px' }}
          />
        </div>
        <button onClick={handleDecryptWithMasterKey} style={{ padding: '10px 20px' }}>
          Descriptografar com MasterKey
        </button>
        {decryptedData && (
          <div style={{ marginTop: '20px' }}>
            <p>
              <strong>Dados Descriptografados:</strong>
            </p>
            <pre style={{ backgroundColor: '#000', padding: '10px', borderRadius: '5px', color: '#fff' }}>
              {decryptedData}
            </pre>
          </div>
        )}
      </section>
    </div>
  );
};

export default App;
