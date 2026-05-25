package pkg

import (
	"net"
	"net/http"
	"strings"
)

// GetClientIP достаёт IP клиента из X-Forwarded-For (если запрос прошёл через
// прокси) либо из RemoteAddr.
func GetClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
