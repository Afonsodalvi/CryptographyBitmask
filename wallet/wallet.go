package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"github.com/ethereum/go-ethereum/crypto"
)

// GenerateMasterKey gera a MasterKey usando apenas o salt e a privateKey
func GenerateMasterKey(salt string, privateKey string) string {
	// Usa Keccak256 para gerar a MasterKey com base apenas na sua saltKey e na chave privada (senha)
	masterKeyBytes := crypto.Keccak256([]byte(salt + privateKey))

	// Retorna a masterKey em formato hexadecimal (sem "0x")
	return fmt.Sprintf("%x", masterKeyBytes)
}


// DeriveKeyFromMaster deriva uma sub-chave da master key usando HMAC-SHA256
//Pense como usar esse metodo, ainda nao implementado da melhor forma
func DeriveKeyFromMaster(masterKey string, context string) []byte {
	h := hmac.New(sha256.New, []byte(masterKey))
	h.Write([]byte(context))
	return h.Sum(nil)
}

// GenerateSalt cria um salt único para cada criptografia
func GenerateSalt() (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}
	return hex.EncodeToString(salt), nil
}

// ApplyBitMask aplica uma bit-mask ao JSON, criptografando apenas os campos especificados pela máscara
func ApplyBitMask(jsonData map[string]interface{}, bitMask string, key []byte) (map[string]interface{}, error) {
	encryptedData := make(map[string]interface{})

	for fieldName, value := range jsonData {
		// Determina se o campo deve ser criptografado com base na bit-mask
		if shouldEncryptField(fieldName, bitMask) {
			// Serializa o campo individualmente
			fieldBytes, err := json.Marshal(value)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal field: %v", err)
			}

			// Cria o bloco de cifra
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, fmt.Errorf("failed to create cipher: %v", err)
			}

			// Gera um vetor de inicialização (IV)
			iv := make([]byte, aes.BlockSize)
			if _, err := io.ReadFull(rand.Reader, iv); err != nil {
				return nil, fmt.Errorf("failed to generate IV: %v", err)
			}

			// Criptografa o campo individualmente
			ciphertext := make([]byte, aes.BlockSize+len(fieldBytes))
			copy(ciphertext[:aes.BlockSize], iv)
			stream := cipher.NewCFBEncrypter(block, iv)
			stream.XORKeyStream(ciphertext[aes.BlockSize:], fieldBytes)

			// Armazena o campo criptografado no novo mapa de dados
			encryptedData[fieldName] = hex.EncodeToString(ciphertext)
		} else {
			// Deixa o campo sem alteração se não for para ser criptografado
			encryptedData[fieldName] = value
		}
	}

	return encryptedData, nil
}

// shouldEncryptField verifica se um campo deve ser criptografado com base na bit-mask
func shouldEncryptField(fieldName, bitMask string) bool {
	// Lógica personalizada para determinar quais campos criptografar com base na máscara
	// Por exemplo, mapeando "name" para o primeiro bit, "age" para o segundo, etc.
	// Aqui, consideramos bitMask uma string binária onde cada bit corresponde a um campo específico.
	switch fieldName {
	case "name":
		return bitMask[0] == '1'
	case "age":
		return bitMask[1] == '1'
	case "email":
		return bitMask[2] == '1'
	default:
		return false
	}
}


// SignAndEncrypt recebe o JSON, a chave mestre e a assinatura, aplica bit-mask e criptografa os dados com a chave derivada e retorna a assinatura
func SignAndEncrypt(jsonData map[string]interface{}, masterKey string, signature string, bitMask string) ([]byte, string, string, error) {
	// Gerar um salt único
	salt, err := GenerateSalt()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate salt: %v", err)
	}

	// Derivar a sub-chave usando a masterKey e o salt
	subKey := DeriveKeyFromMaster(masterKey, salt)

	// Aplicar a bit-mask para criptografar partes específicas do JSON
	encryptedData, err := ApplyBitMask(jsonData, bitMask, subKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to apply bit mask: %v", err)
	}

	// Serializa o JSON criptografado
	encryptedBytes, err := json.Marshal(encryptedData)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to marshal encrypted data: %v", err)
	}

	return encryptedBytes, signature, salt, nil
}

// DecryptWithBitMask descriptografa os dados criptografados usando a chave derivada e bit-mask
func DecryptWithBitMask(encryptedData []byte, masterKey string, salt string, bitMask string) (map[string]interface{}, error) {
	// Derivar a sub-chave usando a masterKey e o salt
	subKey := DeriveKeyFromMaster(masterKey, salt)

	// Deserializa os dados criptografados para map[string]interface{}
	var encryptedMap map[string]interface{}
	if err := json.Unmarshal(encryptedData, &encryptedMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted data: %v", err)
	}

	// Descriptografar os campos específicos com base na bit-mask
	decryptedData := make(map[string]interface{})
	for fieldName, value := range encryptedMap {
		if shouldEncryptField(fieldName, bitMask) {
			ciphertext, err := hex.DecodeString(value.(string))
			if err != nil {
				return nil, fmt.Errorf("failed to decode hex string: %v", err)
			}

			// O IV está nos primeiros 16 bytes (tamanho do bloco AES)
			iv := ciphertext[:aes.BlockSize]
			ciphertext = ciphertext[aes.BlockSize:]

			// Cria o bloco de cifra
			block, err := aes.NewCipher(subKey)
			if err != nil {
				return nil, fmt.Errorf("failed to create cipher: %v", err)
			}

			// Configura o modo de operação para descriptografia
			stream := cipher.NewCFBDecrypter(block, iv)
			stream.XORKeyStream(ciphertext, ciphertext)

			// Deserializa o campo individualmente
			var decryptedField interface{}
			if err := json.Unmarshal(ciphertext, &decryptedField); err != nil {
				return nil, fmt.Errorf("failed to unmarshal decrypted field: %v", err)
			}

			decryptedData[fieldName] = decryptedField
		} else {
			decryptedData[fieldName] = value
		}
	}

	return decryptedData, nil
}
