package deviceBinder

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

func VerifyDeviceKey(baseUrl, fileKey string) error {
	clientkey, err := GenerateNewKeyPair()
	if err != nil {
		return err
	}
	resp, err := http.PostForm(baseUrl+"/exchange", url.Values{
		"keyID":  {base64.StdEncoding.EncodeToString(clientkey.Nonce)},
		"pubKey": {base64.StdEncoding.EncodeToString(clientkey.PublicKey[:])},
	})
	if err != nil {
		return fmt.Errorf("error:%#V", err)
	}
	respText, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf(string(respText))
	}
	serverKey, err := base64.StdEncoding.DecodeString(string(respText))
	if err != nil {
		return err
	}
	clientkey.GenerateSharedKey(serverKey)
	deviceUUID, err := GetDeviceUUID()
	if err != nil {
		return err
	}
	message, err := clientkey.EncryptMessage(fileKey + "|" + deviceUUID)
	if err != nil {
		return err
	}
	resp, err = http.PostForm(baseUrl+"/verify", url.Values{
		"keyID":   {base64.StdEncoding.EncodeToString(clientkey.Nonce)},
		"message": {message},
	})
	if err != nil {
		return fmt.Errorf("error:%#V", err)
	}
	respText, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf(string(respText))
	} else if message, err = clientkey.DecryptMessage(string(respText)); err != nil || message != "ok" {
		return fmt.Errorf("server not verified")
	}
	return nil
}
