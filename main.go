package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	BASE_AUTH     = `WSSE realm="SDP",profile="UsernameToken",type="Appkey"`
	BASE_WSSE_FMT = `UsernameToken Username="%s",PasswordDigest="%s",Nonce="%s",Created="%s"`
	APP_KEY       = `!!!请填写你的appkey,若没有请与哈哈云平台联系!!!`
	APP_SECRET    = `!!!请填写你的appsecret，若没有请与哈哈云平台联系!!!`
)

func wsseHeader(key, secret string) string {
	hasher := sha256.New()
	nonce, _ := randomHex(32)
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	hasher.Write([]byte(nonce + ts + secret))
	digest := base64.StdEncoding.EncodeToString(hasher.Sum(nil))
	return fmt.Sprintf(BASE_WSSE_FMT, key, digest, nonce, ts)
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes), nil
}

func main() {
	fmt.Println("key:", APP_KEY, " secret:", APP_SECRET)
	fmt.Printf("x-wsse: %s\n", wsseHeader(APP_KEY, APP_SECRET))
	fmt.Printf("Authorization: %s\n", BASE_AUTH)
}
