package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

const (
	defaultKey = "xMn29s7rfnSJAXmSo26Aw!3q?4vaCXi5"
)

// Aes advanced encryption standard
type Aes struct {
	Key string
}

// NewAes returns an instance of the Aes struct
func NewAes(key string) *Aes {
	return &Aes{Key: key}
}

// NewAesWithKey returns an instance of the Aes struct with a default key
func NewAesWithKey() *Aes {
	return &Aes{Key: defaultKey}
}

// SetKey sets the cryptation key
func (a *Aes) SetKey(value string) *Aes {
	a.Key = value
	return a
}

// Encrypt encrypts the provided value
func (a Aes) Encrypt(text string) (string, error) {
	return a.encrypt([]byte(a.Key), text)
}

// Decrypt decrypts the provided value
func (a Aes) Decrypt(text string) (string, error) {
	return a.decrypt([]byte(a.Key), text)
}

func (Aes) encrypt(key []byte, text string) (string, error) {
	plainText := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func (Aes) decrypt(key []byte, ctyptoText string) (string, error) {
	cipherText, _ := base64.URLEncoding.DecodeString(ctyptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", errors.New("Cipher text too short")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}
