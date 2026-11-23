package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

type Crypt struct {
	gcm cipher.AEAD
}

func New(passwordFile, saltFile io.Reader) (Crypt, error) {
	password, err := io.ReadAll(passwordFile)
	if err != nil {
		return Crypt{}, fmt.Errorf("error reading password file: %w", err)
	}

	salt, err := io.ReadAll(saltFile)
	if err != nil {
		return Crypt{}, fmt.Errorf("error reading salt file: %w", err)
	}

	key, err := pbkdf2.Key(sha256.New, string(password), salt, 600000, 32)
	if err != nil {
		return Crypt{}, fmt.Errorf("error deriving key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return Crypt{}, fmt.Errorf("error calculating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Crypt{}, fmt.Errorf("error creating GCM: %w", err)
	}

	return Crypt{gcm: gcm}, nil
}

func (c Crypt) Encrypt(r io.Reader) (io.Reader, error) {
	plainText, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("error buffering plain text: %w", err)
	}

	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("error generating nonce: %w", err)
	}

	cipherText := c.gcm.Seal(nonce, nonce, plainText, nil)

	return bytes.NewReader(cipherText), nil
}

func (c Crypt) Decrypt(r io.Reader) (io.Reader, error) {
	cipherText, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("error buffering cypherText: %w", err)
	}

	nonce := cipherText[:c.gcm.NonceSize()]
	cipherText = cipherText[c.gcm.NonceSize():]
	plainText, err := c.gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting cipher text: %w", err)
	}

	return bytes.NewReader(plainText), nil
}
