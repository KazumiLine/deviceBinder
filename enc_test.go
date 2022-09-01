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
	cipherAndSign, err := key1.encryptMessage("fjai3;0lasjdfiou0uy024h3g8fh983wyhf0qjwofj9032jf09jq0fuqh2380rhf08qhq8943hyt09q34fg903yu940yut845yh8ih")
	fmt.Println(cipherAndSign, err)
	plainText, err := key2.decryptMessage(cipherAndSign)
	fmt.Println(plainText, err)
}
