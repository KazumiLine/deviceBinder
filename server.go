package deviceBinder

import (
	"encoding/base64"
	"fmt"
)

var keyPairsMap = map[string]*keyPair{}

func HandleExchangeECDHKey(keyID, pubKeyB64 string) (serverKeyB64 string, err error) {
	serverKey, err := generateNewKeyPair()
	if err != nil {
		return "", err
	}
	serverKey.nonce, err = base64.StdEncoding.DecodeString(keyID)
	if err != nil {
		return "", err
	}
	pubKey, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return "", err
	}
	serverKey.generateSharedKey(pubKey)
	keyPairsMap[keyID] = serverKey
	return base64.StdEncoding.EncodeToString(serverKey.publicKey[:]), nil
}

func HandleEncryptedMessage(keyID, cipherText string, messageChecker func(data string) (err error)) (respText string, err error) {
	if key, ok := keyPairsMap[keyID]; !ok {
		return "", fmt.Errorf("can't find key")
	} else {
		if message, err := key.decryptMessage(cipherText); err != nil {
			return "", err
		} else if err = messageChecker(message); err != nil {
			return "", err
		} else {
			return key.encryptMessage("ok")
		}
	}
}
