package main

import (
	"api/wallet"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"crypto/ecdsa"
	"log"
	"bytes"


	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func main() {
	// Carrega variáveis de ambiente do arquivo .env
	err := godotenv.Load()
	if err != nil {
		panic("Error loading .env file")
	}

	// Defina o modo de execução baseado na variável de ambiente
	gin.SetMode(os.Getenv("GIN_MODE"))

	// Crie um novo router sem os middlewares padrão
	r := gin.New()

	// Adiciona manualmente os middlewares
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// Configura proxies confiáveis (exemplo de configuração para produção)
	r.SetTrustedProxies([]string{"192.168.1.1", "192.168.2.1"}) // Substitua pelos IPs dos seus proxies confiáveis

	// Configura CORS para permitir requisições do front-end
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"}, // Permite a origem do seu front-end
		AllowMethods:     []string{"GET", "POST"},           // Métodos permitidos
		AllowHeaders:     []string{"Origin", "Content-Type"}, // Cabeçalhos permitidos
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Rota para criptografar dados
	r.POST("/encrypt", func(c *gin.Context) {
		var requestData struct {
			JsonData  map[string]interface{} `json:"jsonData"`
			Signature string                 `json:"signature"`
			MasterKey string                 `json:"masterKey"`
			BitMask   string                 `json:"bitMask"`
		}


		if err := c.BindJSON(&requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Criptografar o JSON usando a chave mestre, assinatura e bit-mask
		encryptedData, returnedSignature, salt, err := wallet.SignAndEncrypt(requestData.JsonData, requestData.MasterKey, requestData.Signature, requestData.BitMask)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt data"})
			return 
		}

		fmt.Printf("Received Signature Data: %s\n", requestData.Signature)
		

		c.JSON(http.StatusOK, gin.H{
			"encryptedData": hex.EncodeToString(encryptedData),
			"signature":     returnedSignature,
			"salt":          salt,
		})
	})


		// Rota para descriptografar dados usando a MasterKey
	r.POST("/decrypt-with-masterkey", func(c *gin.Context) {
		var requestData struct {
			EncryptedData   string `json:"encryptedData"`
			MasterKey       string `json:"masterKey"`
			SaltKey 		string `json:"SaltKey"`
			PrivateKey      string `json:"privateKey"`
			Salt            string `json:"salt"`
			BitMask         string `json:"bitMask"`
			UserSignature   string `json:"userSignature"`
			UserAddress     string `json:"userAddress"`
		}

		if err := c.BindJSON(&requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}


		fmt.Printf("Received Encrypted Data: %s\n", requestData.EncryptedData)
		fmt.Printf("Received Salt: %s\n", requestData.Salt)
		fmt.Printf("Received BitMask: %s\n", requestData.BitMask)
		fmt.Printf("Received BitMask: %s\n", requestData.UserSignature)

		// Gerar a MasterKey no backend para validar
		generatedMasterKey := wallet.GenerateMasterKey(requestData.SaltKey, requestData.PrivateKey)
		fmt.Printf("Generated MasterKey (Backend): %s\n", generatedMasterKey)
		fmt.Printf("Received MasterKey (Frontend): %s\n", requestData.MasterKey)

		// Comparar a masterKey recebida com a gerada
		if generatedMasterKey != requestData.MasterKey[2:] { // Remove "0x" do Frontend
			fmt.Println("MasterKey mismatch!")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "MasterKey inválida ou informações incorretas"})
			return
		}

		// Validar que e a private key correta que esta assinando
		//Obs. Ainda nao implementado da melhor forma
		privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")//privatekey de test
		if err != nil {
			log.Fatal(err)
		}

		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
		}

		publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

		encryptedHash := crypto.Keccak256Hash([]byte(requestData.EncryptedData)) // Hash da mensagem criptografada
		fmt.Printf("Hash dos dados criptografados (Backend): %x\n", encryptedHash.Hex())

		signature, err := crypto.Sign(encryptedHash.Bytes(), privateKey)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(hexutil.Encode(signature))  

		sigPublicKey, err := crypto.Ecrecover(encryptedHash.Bytes(), signature)
		if err != nil {
			log.Fatal(err)
		}

		matches := bytes.Equal(sigPublicKey, publicKeyBytes)
		fmt.Println(matches) // true

		sigPublicKeyECDSA, err := crypto.SigToPub(encryptedHash.Bytes(), signature)
		if err != nil {
			log.Fatal(err)
		}

		sigPublicKeyBytes := crypto.FromECDSAPub(sigPublicKeyECDSA)
		matches = bytes.Equal(sigPublicKeyBytes, publicKeyBytes)
		fmt.Println(matches) // true

		signatureNoRecoverID := signature[:len(signature)-1] // remove recovery id
		verified := crypto.VerifySignature(publicKeyBytes, encryptedHash.Bytes(), signatureNoRecoverID)
		fmt.Println(verified) // true


		///decriptar logic
		
		encryptedBytes, err := hex.DecodeString(requestData.EncryptedData)
		if err != nil {
			fmt.Printf("Failed to decode encrypted data: %v\n", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid encrypted data format"})
			return
		}

		fmt.Printf("Decoded Encrypted Bytes: %x\n", encryptedBytes)

		// Agora descriptografar os dados com a chave master validada
		decryptedData, err := wallet.DecryptWithBitMask(encryptedBytes, requestData.MasterKey, requestData.Salt, requestData.BitMask)
		if err != nil {
			fmt.Printf("Failed to decrypt data: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt data"})
			return
		}

		fmt.Printf("Decrypted Data: %v\n", decryptedData)

		c.JSON(http.StatusOK, gin.H{"decryptedData": decryptedData})
	})


	// Inicia o servidor na porta 8080
	r.Run(":8080")
}
