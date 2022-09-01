package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/KazumiLine/deviceBinder"
)

func startServer() {
	userData := map[string]string{}
	http.HandleFunc("/exchange", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			pubkey, err := deviceBinder.HandleExchangeECDHKey(r.FormValue("keyID"), r.FormValue("pubKey"))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
			} else {
				w.Write([]byte(pubkey))
			}
		}
	})
	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			checker := func(message string) (err error) {
				data := strings.Split(message, "|")
				if len(data) == 2 {
					if uuid, ok := userData[data[0]]; !ok || uuid == data[1] {
						userData[data[0]] = data[1]
						return nil
					}
				}
				return fmt.Errorf("device already registered")
			}
			respText, err := deviceBinder.HandleEncryptedMessage(r.FormValue("keyID"), r.FormValue("message"), checker)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
			} else {
				w.Write([]byte(respText))
			}
		}
	})
	http.ListenAndServe(":8080", nil)
}

func startClient(url string) {
	fmt.Println(deviceBinder.VerifyDeviceKey(url, "testfile"))
}

func main() {
	if len(os.Args) == 2 {
		if os.Args[1] == "s" {
			startServer()
		} else {
			startClient(os.Args[1])
		}
	} else {
		fmt.Println("")
	}
}
