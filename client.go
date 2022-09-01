package deviceBinder

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func VerifyDeviceKey(url, fileKey string) error {
	clientkey, err := generateNewKeyPair()
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/x-www-form-urlencoded",
		strings.NewReader("keyID="+base64.RawStdEncoding.EncodeToString(clientkey.nonce[:])+"&pubKey="+base64.StdEncoding.EncodeToString(clientkey.publicKey[:])))
	if err != nil {
		return err
	}
	serverKey, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	clientkey.generateSharedKey(serverKey)
	deviceUUID, err := getDeviceUUID()
	if err != nil {
		return err
	}
	message, err := clientkey.encryptMessage(fileKey + "|" + deviceUUID)
	if err != nil {
		return err
	}
	resp, err = http.Post(url, "application/x-www-form-urlencoded", strings.NewReader("keyID="+base64.RawStdEncoding.EncodeToString(clientkey.nonce[:])+"&message="+message))
	respText, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if message, err = clientkey.decryptMessage(string(respText)); err != nil || message != "ok" {
		return fmt.Errorf("server not verified")
	}
	return nil
}
