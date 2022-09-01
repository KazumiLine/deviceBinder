package deviceBinder

import (
	"fmt"
	"testing"
)

func TestGenerateNewKeyPair(t *testing.T) {
	key, err := GenerateNewKeyPair()
	fmt.Println(key, err)
}

func TestGenerateSharedKey(t *testing.T) {
	key1, err := GenerateNewKeyPair()
	key2, err := GenerateNewKeyPair()
	key1.GenerateSharedKey(key2.PublicKey[:])
	key2.GenerateSharedKey(key1.PublicKey[:])
	fmt.Println(key1.SharedKey, key2.SharedKey, err)
}

func TestEncryptMessage(t *testing.T) {
	key1, err := GenerateNewKeyPair()
	key2, err := GenerateNewKeyPair()
	key1.GenerateSharedKey(key2.PublicKey[:])
	key2.GenerateSharedKey(key1.PublicKey[:])
	key2.Nonce = key1.Nonce
	cipherAndSign, err := key1.EncryptMessage("HIHI")
	fmt.Println(cipherAndSign, err)
	plainText, err := key2.DecryptMessage(cipherAndSign)
	fmt.Println(plainText, err)
}
