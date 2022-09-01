package deviceBinder

import (
	"fmt"
	"testing"
)

func TestGenerateNewKeyPair(t *testing.T) {
	key, err := generateNewKeyPair()
	fmt.Println(key, err)
}

func TestGenerateSharedKey(t *testing.T) {
	key1, err := generateNewKeyPair()
	key2, err := generateNewKeyPair()
	key1.generateSharedKey(key2.publicKey[:])
	key2.generateSharedKey(key1.publicKey[:])
	fmt.Println(key1.sharedKey, key2.sharedKey, err)
}

func TestEncryptMessage(t *testing.T) {
	key1, err := generateNewKeyPair()
	key2, err := generateNewKeyPair()
	key1.generateSharedKey(key2.publicKey[:])
	key2.generateSharedKey(key1.publicKey[:])
	key2.nonce = key1.nonce
	cipherAndSign, err := key1.encryptMessage("Hello")
	fmt.Println(cipherAndSign, err)
	plainText, err := key2.decryptMessage(cipherAndSign)
	fmt.Println(plainText, err)
}
