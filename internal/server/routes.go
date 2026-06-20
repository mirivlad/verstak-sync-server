package server

func (s *Server) routes() {
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/device/register", s.handleDeviceRegister)
	s.mux.HandleFunc("/api/v1/sync/push", s.handleSyncPush)
	s.mux.HandleFunc("/api/v1/sync/pull", s.handleSyncPull)
	s.mux.HandleFunc("/api/v1/blobs/", s.handleBlobs)
	s.mux.HandleFunc("/api/client/pair", s.handleClientPair)
	s.mux.HandleFunc("/api/auth/test", s.handleAuthTest)
	s.mux.HandleFunc("/api/client/revoke-current", s.handleClientRevoke)
	s.mux.HandleFunc("/api/client/me", s.handleClientMe)
	s.mux.HandleFunc("/api/client/revoke-device", s.handleClientRevokeDevice)
	s.mux.HandleFunc("/api/v1/auth/register", s.handleRegister)
	s.mux.HandleFunc("/api/v1/auth/confirm", s.handleConfirm)
	s.mux.HandleFunc("/api/v1/auth/login", s.handleUserLogin)
	s.mux.HandleFunc("/api/v1/auth/forgot", s.handleForgot)
	s.mux.HandleFunc("/api/v1/auth/reset", s.handleReset)
	s.mux.HandleFunc("/admin/login", s.handleAdminLogin)
	s.mux.HandleFunc("/admin/dashboard", s.handleAdminDashboard)
	s.mux.HandleFunc("/admin/users", s.handleAdminUsers)
	s.mux.HandleFunc("/admin/devices", s.handleAdminDevices)
	s.mux.HandleFunc("/", s.handleNotFound)
}
