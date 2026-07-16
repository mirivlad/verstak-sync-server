package server

import (
	"math"
	"net/http"
	"strings"
	"time"
)

var ratePolicies = map[string]RatePolicy{
	"pair":            {Limit: 5, Window: 15 * time.Minute},
	"device-register": {Limit: 5, Window: 15 * time.Minute},
	"auth-test":       {Limit: 10, Window: 10 * time.Minute},
	"login":           {Limit: 10, Window: 10 * time.Minute},
	"register":        {Limit: 5, Window: time.Hour},
	"forgot":          {Limit: 5, Window: time.Hour},
	"reset":           {Limit: 8, Window: time.Hour},
	"admin-reset":     {Limit: 8, Window: time.Hour},
}

// allowRate applies an IP limit and, where a login/account is supplied, an
// additional bounded account bucket. It never logs submitted credentials.
func (s *Server) allowRate(w http.ResponseWriter, r *http.Request, action, account string) bool {
	policy, ok := ratePolicies[action]
	if !ok {
		return true
	}
	ip := s.clientIP(r)
	s.limiter.Cleanup(2 * policy.Window)
	keys := []string{action + ":ip:" + ip}
	account = strings.ToLower(strings.TrimSpace(account))
	if account != "" {
		// Keep attacker-controlled account strings out of the in-memory key and
		// audit path while preserving an independent per-account bucket.
		keys = append(keys, action+":account:"+sha256Hex(account))
	}
	for _, key := range keys {
		if allowed, retryAfter := s.limiter.Allow(key, policy); !allowed {
			seconds := int(math.Ceil(retryAfter.Seconds()))
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconvItoa(seconds))
			s.auditLog("rate_limit_exceeded", "", "", ip, "rate limit: "+action)
			jsonErr(w, http.StatusTooManyRequests, "too many attempts")
			return false
		}
	}
	return true
}

func strconvItoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	if negative {
		index--
		digits[index] = '-'
	}
	return string(digits[index:])
}
