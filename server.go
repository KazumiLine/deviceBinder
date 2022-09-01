package deviceBinder

import (
	"encoding/base64"
	"fmt"
)

var keyPairsMap = map[string]*KeyPair{}

func HandleExchangeECDHKey(keyID, pubKeyB64 string) (serverKeyB64 string, err error) {
	serverKey, err := GenerateNewKeyPair()
	if err != nil {
		return "", err
	}
	serverKey.Nonce, err = base64.StdEncoding.DecodeString(keyID)
	if err != nil {
		return "", err
	}
	pubKey, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return "", err
	}
	serverKey.GenerateSharedKey(pubKey)
	keyPairsMap[keyID] = serverKey
	return base64.StdEncoding.EncodeToString(serverKey.PublicKey[:]), nil
}

func HandleEncryptedMessage(keyID, cipherText string, messageChecker func(data string) (err error)) (respText string, err error) {
	if key, ok := keyPairsMap[keyID]; !ok {
		return "", fmt.Errorf("can't find key")
	} else {
		if message, err := key.DecryptMessage(cipherText); err != nil {
			return "", err
		} else if err = messageChecker(message); err != nil {
			return "", err
		} else {
			return key.EncryptMessage("ok")
		}
	}
}
