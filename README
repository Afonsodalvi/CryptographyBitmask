# Criptografia + Bitmask (Cryptography + Bitmask)

Este repositório demonstra diversos métodos de criptografia e o uso de assinaturas de mensagens na blockchain.
(This repository demonstrates various cryptographic methods and the use of message signatures on the blockchain.)

É necessário ter em sua máquina:
(You will need the following on your machine:)

- Go lang: [Go](https://go.dev/)

- Node.js: [Node.js](https://nodejs.org/en/download/package-manager)

Comandos para iniciar o projeto localmente:
(Commands to start the project locally:)

```javascript
go run main.go
```

Inicialização do front-end em React + TypeScript + Vite:
(Initialize the front-end with React + TypeScript + Vite:)

```javascript
cd crypto-app
npm install
npm run dev
```
Comece a usar: [localhost](http://localhost:5173/)
Start using: [localhost](http://localhost:5173/)


### Metodos usados (Methods Used:):

1. Keccak256 (SHA-3): No método `GenerateMasterKey` para gerar uma chave mestra única baseada em uma combinação de saltKey e privateKey.
(Keccak256 (SHA-3): In the GenerateMasterKey method to generate a unique master key based on a combination of saltKey and privateKey.)

2. AES (Advanced Encryption Standard) em Modo CFB (Cipher Feedback): No método `ApplyBitMask` para criptografar campos de um JSON selecionados pela bitmask, e no método `DecryptWithBitMask` para descriptografar esses mesmos dados. (AES (Advanced Encryption Standard) in CFB (Cipher Feedback) Mode: In the ApplyBitMask method to encrypt fields of a JSON selected by the bitmask, and in the DecryptWithBitMask method to decrypt the same data.)

3. HMAC-SHA256: No método `DeriveKeyFromMaster` para gerar uma sub-chave da chave mestra usando HMAC (Hash-based Message Authentication Code) com SHA-256. (HMAC-SHA256: In the DeriveKeyFromMaster method to generate a sub-key from the master key using HMAC (Hash-based Message Authentication Code) with SHA-256.)

4. Vetor de Inicialização (IV) Aleatório: No método `ApplyBitMask`, ao gerar o iv para criptografia com AES. (Random Initialization Vector (IV): In the ApplyBitMask method, when generating the IV for AES encryption.)

5. BitMask: Permite escolher quais partes dos dados devem ser criptografadas. (BitMask: Allows selecting which parts of the data should be encrypted.)

### Assinatura de Mensagens com ECDSA (Message Signing with ECDSA):

- Os usuários assinam mensagens antes de enviar os dados para a API, e a API valida essas assinaturas para garantir que os dados sejam autênticos.
(Essa etapa ainda pode ser ajustada). Users sign messages before sending data to the API, and the API validates these signatures to ensure the data is authentic. (This step can still be adjusted)
