package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"unicode/utf8"
)

func DecryptValue(valueB64 string, protoID int) (string, error) {
	// key = ("key_{proto_id}" + zeroes)[:16]
	keyStr := fmt.Sprintf("key_%d", protoID)
	key := make([]byte, 16)
	copy(key, []byte(keyStr))
	iv := key // IV = key (as in the Python)

	// Base64 decode
	data, err := base64.StdEncoding.DecodeString(valueB64)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	if len(data)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext length (%d) is not a multiple of block size (%d)", len(data), aes.BlockSize)
	}

	// AES CBC decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)

	// PKCS5-style trim based on last byte (same permissive check as Python)
	if n := len(out); n > 0 {
		pad := int(out[n-1])
		if pad > 0 && pad <= aes.BlockSize && pad <= n {
			out = out[:n-pad]
		}
	}

	// Convert to string, ignoring invalid UTF-8 (like Python's errors="ignore")
	return bytesToStringIgnoreInvalid(out), nil
}

// Drop invalid UTF-8 bytes (mimics Python .decode(errors="ignore"))
func bytesToStringIgnoreInvalid(b []byte) string {
	var buf bytes.Buffer
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			// invalid byte — skip it
			b = b[1:]
			continue
		}
		buf.WriteRune(r)
		b = b[size:]
	}
	return buf.String()
}
