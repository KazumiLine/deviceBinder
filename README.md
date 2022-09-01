Golang 編譯檔激活碼驗證
===============

### 發想
隨著程式的開發，有些客戶希望可以購買檔案讓他們自己運行。
為了防止檔案的外流與濫用，希望可以設計一個綁定系統。
在用戶無法逆向我的編譯檔的前提下，檔案連到我的server做驗證。
開通 寫死or給予的驗證碼後，連帶著用戶端裝置的UUID一同發到server端驗證並綁定。

### 特色
- 使用ECDH-AESCBC進行加密
- 使用Hmac-SHA256進行簽章
- 使用硬體UUID進行綁定
- 支援windows/linux

### 流程
- 初次連線，交換publicKey，產生sharedKey
- 讀取用戶裝置的硬體編號
- 連線至server進行驗證
- 若收到正確回覆即可開始運作


Getting Started
===============

## Installing

To start using GJSON, install Go and run `go get`:

```sh
$ go get -u github.com/KazumiLine/deviceBinder
```

## Setup Server Key
To set the key between server and client.
```go
deviceBinder.SetServerKey(key)
```

## Server Site
You can impl the func to your own site.
```go=
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
        // client will send data like filename|deviceID
        // impl your own checker(data string) (err error)
        respText, err := deviceBinder.HandleEncryptedMessage(r.FormValue("keyID"), r.FormValue("message"), checker)
        if err != nil {
            w.WriteHeader(http.StatusInternalServerError)
            w.Write([]byte(err.Error()))
        } else {
            w.Write([]byte(respText))
        }
    }
})
```

## Client Site
You can make your own verify method.
See [client.go](https://github.com/KazumiLine/deviceBinder/blob/master/client.go)
Or Call `VerifyDeviceKey(Url, filename)` directly

## Some Util
```go=
deviceBinder.GetDeviceUUID()

keyPair, err := deviceBinder.GenerateNewKeyPair() (key *KeyPair, err error)
keyPair.GenerateSharedKey(peersPublicKey []byte)

// You must generate shared key before encrypt/decrypt
keyPair.EncryptMessage(message string)
keyPair.DecryptMessage(cipherAndSignB64 string)

```