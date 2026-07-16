package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonOKStatus(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	jsonErrCode(w, code, defaultErrorCode(code), msg)
}

// jsonErrCode preserves the legacy human-readable error field while giving
// Desktop a stable machine-readable code for localized messages.
func jsonErrCode(w http.ResponseWriter, status int, machineCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg, "code": machineCode})
}

func defaultErrorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limited"
	default:
		return "internal_error"
	}
}

func jsonInternalError(w http.ResponseWriter, err error) {
	log.Printf("request failed: %v", err)
	jsonErr(w, http.StatusInternalServerError, "internal error")
}

func methodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	jsonErrCode(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

// decodeJSONBody enforces a hard byte limit, rejects a second JSON value, and
// keeps all request handlers on the same error contract.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, destination interface{}, limit int64) bool {
	if limit <= 0 {
		limit = 1
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(destination); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			jsonErrCode(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
			return false
		}
		jsonErrCode(w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return false
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			jsonErrCode(w, http.StatusBadRequest, "trailing_json", "request must contain one JSON value")
		} else {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				jsonErrCode(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
			} else {
				jsonErrCode(w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
			}
		}
		return false
	}
	return true
}

func validateStringLength(name, value string, max int) error {
	if len(value) > max {
		return fmt.Errorf("%s is too long", name)
	}
	return nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
