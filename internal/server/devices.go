package server

import (
	"fmt"
)

func validatePairRequest(login, deviceName, clientVersion, vaultID string) error {
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"login", login, maxLoginLength},
		{"device name", deviceName, maxDeviceNameLength},
		{"client version", clientVersion, maxClientVersionLength},
		{"vault id", vaultID, maxVaultIDLength},
	} {
		if err := validateStringLength(field.name, field.value, field.max); err != nil {
			return err
		}
	}
	if vaultID == "" {
		return fmt.Errorf("vault_id required")
	}
	return nil
}

func (s *Server) revokeDevice(deviceID, when string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE server_devices SET revoked_at=? WHERE id=?", when, deviceID); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM server_sessions WHERE subject_id=? AND scope='device'", deviceID); err != nil {
		return err
	}
	return tx.Commit()
}
