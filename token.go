package nosurf

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
)

const (
	tokenLength = 32
)

func generateToken() []byte {
	bytes := make([]byte, tokenLength)

	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}

	return bytes
}

// verifyToken expects the realToken to be unmasked and the sentToken to be masked
func verifyToken(realToken, sentToken []byte) bool {
	realN := len(realToken)
	sentN := len(sentToken)

	if realN == tokenLength && sentN == 2*tokenLength {
		return tokensEqual(realToken, unmaskToken(sentToken))
	}
	return false
}

// tokensEqual expects both tokens to be unmasked
func tokensEqual(realToken, sentToken []byte) bool {
	return len(realToken) == tokenLength &&
		len(sentToken) == tokenLength &&
		subtle.ConstantTimeCompare(realToken, sentToken) == 1
}

func init() {
	buf := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, buf)

	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}
}

// VerifyToken verifies the sent token equals the real one
// func VerifyToken(realToken, sentToken string) bool {
// 	r, err := base64.StdEncoding.DecodeString(realToken)
// 	if err != nil {
// 		return false
// 	}
// 	if len(r) == 2*tokenLength {
// 		r = unmaskToken(r)
// 	}
// 	s, err := base64.StdEncoding.DecodeString(sentToken)
// 	if err != nil {
// 		return false
// 	}
// 	if len(s) == 2*tokenLength {
// 		s = unmaskToken(s)
// 	}
// 	return tokensEqual(r, s)
// }
