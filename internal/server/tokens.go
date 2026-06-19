package server

import (
	"crypto/rand"
	"encoding/hex"
)

func genDeviceToken() (token, prefix, suffix string) {
	b := make([]byte, 32)
	rand.Read(b)
	token = hex.EncodeToString(b)
	prefix = token[:8]
	suffix = token[len(token)-4:]
	return
}
