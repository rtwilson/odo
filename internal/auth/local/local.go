package local

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func NewToken(prefix string, bytesLen int) (string, error) {
	if bytesLen <= 0 {
		bytesLen = 32
	}
	random := make([]byte, bytesLen)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(random), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func SessionIDFromToken(token string) string {
	if strings.HasPrefix(token, "sess_") {
		if index := strings.Index(token, "."); index > len("sess_") {
			return token[:index]
		}
	}
	parts := strings.SplitN(token, "_", 3)
	if len(parts) < 3 || parts[0] != "sess" {
		return ""
	}
	return "sess_" + parts[1]
}
