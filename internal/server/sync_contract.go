package server

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	maxOpIDLength           = 128
	maxEntityTypeLength     = 64
	maxEntityIDLength       = 4096
	maxOpTypeLength         = 64
	maxIdempotencyKeyLength = 128
	maxDeviceIDLength       = 128
	maxDeviceNameLength     = 128
	maxClientVersionLength  = 256
	maxVaultIDLength        = 256
	maxLoginLength          = 320
)

type syncPushOperation struct {
	OpID              string `json:"op_id"`
	EntityType        string `json:"entity_type"`
	EntityID          string `json:"entity_id"`
	OpType            string `json:"op_type"`
	PayloadJSON       string `json:"payload_json"`
	ClientSequence    int    `json:"client_sequence"`
	LastSeenServerSeq int    `json:"last_seen_server_seq"`
	CreatedAt         string `json:"created_at"`
}

type syncPushRequest struct {
	DeviceID       string              `json:"device_id"`
	IdempotencyKey string              `json:"idempotency_key"`
	Ops            []syncPushOperation `json:"ops"`
}

type syncPullRequest struct {
	SinceSequence int `json:"since_sequence"`
	PageLimit     int `json:"page_limit"`
}

func (s *Server) validateSyncPush(req syncPushRequest) (code, message string) {
	if len(req.Ops) > s.cfg.Limits.MaxPushOperations {
		return "too_many_operations", "too many operations in one push"
	}
	for name, value := range map[string]struct {
		value string
		max   int
	}{
		"device_id":       {req.DeviceID, maxDeviceIDLength},
		"idempotency_key": {req.IdempotencyKey, maxIdempotencyKeyLength},
	} {
		if err := validateStringLength(name, value.value, value.max); err != nil {
			return "field_too_long", err.Error()
		}
	}
	for _, op := range req.Ops {
		for _, value := range []struct {
			name  string
			value string
			max   int
		}{
			{"op_id", op.OpID, maxOpIDLength},
			{"entity_type", op.EntityType, maxEntityTypeLength},
			{"entity_id", op.EntityID, maxEntityIDLength},
			{"op_type", op.OpType, maxOpTypeLength},
		} {
			if strings.TrimSpace(value.value) == "" {
				return "invalid_operation", fmt.Sprintf("%s is required", value.name)
			}
			if err := validateStringLength(value.name, value.value, value.max); err != nil {
				return "field_too_long", err.Error()
			}
		}
		if len(op.PayloadJSON) > s.cfg.Limits.MaxPayloadJSON {
			return "payload_too_large", "operation payload is too large"
		}
		if op.PayloadJSON != "" && !json.Valid([]byte(op.PayloadJSON)) {
			return "invalid_payload", "operation payload_json must be valid JSON"
		}
		if op.ClientSequence < 0 || op.LastSeenServerSeq < 0 {
			return "invalid_operation", "operation sequences must be non-negative"
		}
	}
	return "", ""
}

func (s *Server) pullPageLimit(requested int) int {
	if requested <= 0 || requested > s.cfg.Limits.MaxPullPage {
		return s.cfg.Limits.MaxPullPage
	}
	return requested
}
