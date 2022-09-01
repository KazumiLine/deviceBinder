package deviceBinder

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

var serverKey string = "MustBeSameBothServerAndClient"

func SetServerKey(key string) {
	serverKey = key
}

type KeyPair struct {
	Nonce      []byte
	PrivateKey [32]byte
	PublicKey  [32]byte
	SharedKey  []byte
}

func GenerateNewKeyPair() (key *KeyPair, err error) {
	key = new(KeyPair)
	key.Nonce = make([]byte, 16)
	_, err = rand.Reader.Read(key.Nonce[:])
	if err != nil {
		return nil, err
	}
	_, err = rand.Reader.Read(key.PrivateKey[:])
	if err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&key.PublicKey, &key.PrivateKey)
	return key, nil
}

func (key *KeyPair) GenerateSharedKey(peersPublicKey []byte) {
	var peersPublicKey32, sharedKey [32]byte
	copy(peersPublicKey32[:], peersPublicKey)
	copy(sharedKey[:], key.SharedKey)
	curve25519.ScalarMult(&sharedKey, &key.PrivateKey, &peersPublicKey32)
	key.SharedKey = sharedKey[:]
}

func aesCBCEncrypt(encodeBytes, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	encodeBytes = pkcs7Padding(encodeBytes, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(encodeBytes))
	blockMode.CryptBlocks(crypted, encodeBytes)
	return crypted, nil
}

func aesCBCDecrypt(encryptedData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedData, encryptedData)
	encryptedData = pkcs7UnPadding(encryptedData)
	return encryptedData, nil
}

func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func (key *KeyPair) EncryptMessage(content string) (cipherAndSign string, err error) {
	if len(key.SharedKey) == 0 {
		return "", fmt.Errorf("please generate shared key first")
	}
	masterKey := sha256.Sum256(append(append([]byte(serverKey), key.SharedKey[:]...), key.Nonce...))
	hmacKey := sha256.Sum256(append([]byte("hmac_key"), masterKey[:]...))
	cipherText, err := aesCBCEncrypt([]byte(content), masterKey[:16], masterKey[16:32])
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, hmacKey[:])
	h.Write(cipherText)
	return base64.StdEncoding.EncodeToString(h.Sum(cipherText)), nil
}

func (key *KeyPair) DecryptMessage(cipherAndSignB64 string) (content string, err error) {
	if len(key.SharedKey) == 0 {
		return "", fmt.Errorf("please generate shared key first")
	}
	cipherAndSign, err := base64.StdEncoding.DecodeString(cipherAndSignB64)
	if err != nil {
		return "", err
	}
	masterKey := sha256.Sum256(append(append([]byte(serverKey), key.SharedKey[:]...), key.Nonce...))
	hmacKey := sha256.Sum256(append([]byte("hmac_key"), masterKey[:]...))
	h := hmac.New(sha256.New, hmacKey[:])
	h.Write(cipherAndSign[:len(cipherAndSign)-32])
	if !hmac.Equal(h.Sum(nil), cipherAndSign[len(cipherAndSign)-32:]) {
		return "", fmt.Errorf("invalid signature")
	}
	plainText, err := aesCBCDecrypt(cipherAndSign[:len(cipherAndSign)-32], masterKey[:16], masterKey[16:32])
	if err != nil {
		return
	}
	return string(plainText), nil
}
