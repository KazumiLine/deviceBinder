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

type keyPair struct {
	nonce      []byte
	privateKey [32]byte
	publicKey  [32]byte
	sharedKey  [32]byte
}

func generateNewKeyPair() (key *keyPair, err error) {
	key = new(keyPair)
	key.nonce = make([]byte, 0)
	_, err = rand.Reader.Read(key.nonce[:])
	if err != nil {
		return nil, err
	}
	_, err = rand.Reader.Read(key.privateKey[:])
	if err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&key.publicKey, &key.privateKey)
	return key, nil
}

func (key *keyPair) generateSharedKey(peersPublicKey []byte) {
	var peersPublicKey32 [32]byte
	copy(peersPublicKey32[:], peersPublicKey)
	curve25519.ScalarMult(&key.sharedKey, &key.privateKey, &peersPublicKey32)
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

func (key *keyPair) encryptMessage(content string) (cipherAndSign string, err error) {
	masterKey := sha256.Sum256(append(append([]byte(serverKey), key.sharedKey[:]...), key.nonce...))
	hmacKey := sha256.Sum256(append([]byte("hmac_key"), masterKey[:]...))
	cipherText, err := aesCBCEncrypt([]byte(content), masterKey[:16], masterKey[16:32])
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, hmacKey[:])
	h.Write(cipherText)
	return base64.StdEncoding.EncodeToString(h.Sum(cipherText)), nil
}

func (key *keyPair) decryptMessage(cipherAndSignB64 string) (content string, err error) {
	cipherAndSign, err := base64.StdEncoding.DecodeString(cipherAndSignB64)
	if err != nil {
		return "", err
	}
	masterKey := sha256.Sum256(append(append([]byte(serverKey), key.sharedKey[:]...), key.nonce...))
	hmacKey := sha256.Sum256(append([]byte("hmac_key"), masterKey[:]...))
	h := hmac.New(sha256.New, hmacKey[:])
	h.Write(cipherAndSign[:16])
	if !hmac.Equal(h.Sum(nil), cipherAndSign[16:]) {
		return "", fmt.Errorf("invalid signature")
	}
	plainText, err := aesCBCDecrypt(cipherAndSign[:16], masterKey[:16], masterKey[16:32])
	if err != nil {
		return
	}
	return string(plainText), nil
}
