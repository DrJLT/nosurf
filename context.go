package nosurf

import (
	"encoding/base64"
	"net/http"
)

type ctxKey int

const (
	nosurfKey ctxKey = iota
)

type csrfContext struct {
	token string
}

// Token won't be available after CSRFHandler finishes
func Token(req *http.Request) string {
	ctx, ok := req.Context().Value(nosurfKey).(*csrfContext)
	if !ok {
		return ""
	}
	return ctx.token
}

func ctxSetToken(req *http.Request, token []byte) {
	ctx := req.Context().Value(nosurfKey).(*csrfContext)
	ctx.token = base64.StdEncoding.EncodeToString(maskToken(token))
}
