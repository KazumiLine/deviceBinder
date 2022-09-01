package deviceBinder

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

func VerifyDeviceKey(baseUrl, fileKey string) error {
	clientkey, err := generateNewKeyPair()
	if err != nil {
		return err
	}
	resp, err := http.PostForm(baseUrl+"/exchange", url.Values{
		"keyID":  {base64.StdEncoding.EncodeToString(clientkey.nonce)},
		"pubKey": {base64.StdEncoding.EncodeToString(clientkey.publicKey[:])},
	})
	if err != nil || resp.StatusCode != 200 {
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
	resp, err = http.PostForm(baseUrl+"/verify", url.Values{
		"keyID":   {base64.StdEncoding.EncodeToString(clientkey.nonce)},
		"message": {message},
	})
	if err != nil || resp.StatusCode != 200 {
		return err
	}
	respText, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Println(string(respText))
	if message, err = clientkey.decryptMessage(string(respText)); err != nil || message != "ok" {
		fmt.Println(message, err)
		return fmt.Errorf("server not verified")
	}
	return nil
}
