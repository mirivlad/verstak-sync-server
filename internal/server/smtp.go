package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"time"
)

func (s *Server) smtpGet(key string) string {
	var val string
	s.db.QueryRow("SELECT value FROM server_smtp_config WHERE key=?", key).Scan(&val)
	return val
}

func (s *Server) smtpSet(key, val string) error {
	_, err := s.db.Exec("INSERT OR REPLACE INTO server_smtp_config (key, value) VALUES (?, ?)", key, val)
	return err
}

func sel(v, want string) string {
	if v == want {
		return " selected"
	}
	return ""
}

func (s *Server) smtpConnect(host, port, user, pass, security string) (*smtp.Client, error) {
	addr := net.JoinHostPort(host, port)
	switch security {
	case "tls":
		tlsCfg := &tls.Config{ServerName: host}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("tls dial: %w", err)
		}
		cl, err := smtp.NewClient(conn, host)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("smtp client: %w", err)
		}
		return cl, nil
	default:
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("connect: %w", err)
		}
		cl, err := smtp.NewClient(conn, host)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("smtp client: %w", err)
		}
		if security != "none" {
			if ok, _ := cl.Extension("STARTTLS"); ok {
				tlsCfg := &tls.Config{ServerName: host}
				if err := cl.StartTLS(tlsCfg); err != nil {
					cl.Close()
					return nil, fmt.Errorf("starttls: %w", err)
				}
			}
		}
		return cl, nil
	}
}

func (s *Server) smtpSendMsg(cl *smtp.Client, user, pass, host, from, to string, msg []byte) error {
	if user != "" {
		auth := smtp.PlainAuth("", user, pass, host)
		if err := cl.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := cl.Mail(from); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	if err := cl.Rcpt(to); err != nil {
		return fmt.Errorf("rcpt: %w", err)
	}
	w, err := cl.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		w.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

func (s *Server) smtpSend(to, subject, body string) error {
	host := s.smtpGet("smtp_host")
	port := s.smtpGet("smtp_port")
	user := s.smtpGet("smtp_user")
	pass := s.smtpGet("smtp_pass")
	from := s.smtpGet("smtp_from")
	security := s.smtpGet("smtp_security")
	if host == "" || port == "" || from == "" {
		err := fmt.Errorf("SMTP not configured")
		log.Printf("smtp: %v (to=%s)", err, to)
		return err
	}
	var ok bool
	if from, ok = normalizeEmailAddress(from); !ok {
		return fmt.Errorf("invalid SMTP sender address")
	}
	if to, ok = normalizeEmailAddress(to); !ok {
		return fmt.Errorf("invalid SMTP recipient address")
	}
	log.Printf("smtp: sending to %s via %s:%s (security=%s)", to, host, port, security)
	msg := []byte("From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" + body + "\r\n")
	cl, err := s.smtpConnect(host, port, user, pass, security)
	if err != nil {
		log.Printf("smtp: connect error: %v", err)
		return err
	}
	defer cl.Close()
	if err := s.smtpSendMsg(cl, user, pass, host, from, to, msg); err != nil {
		log.Printf("smtp: send error: %v", err)
		return err
	}
	log.Printf("smtp: sent OK to %s", to)
	return nil
}

func (s *Server) smtpTest(host, port, user, pass, security, from, to string) error {
	if host == "" || port == "" || from == "" {
		return fmt.Errorf("SMTP not configured")
	}
	var ok bool
	if from, ok = normalizeEmailAddress(from); !ok {
		return fmt.Errorf("invalid SMTP sender address")
	}
	if to, ok = normalizeEmailAddress(to); !ok {
		return fmt.Errorf("invalid SMTP recipient address")
	}
	msg := []byte("From: " + from + "\r\nTo: " + to + "\r\nSubject: Test from Verstak Sync\r\n\r\nThis is a test email from Verstak Sync Server.\r\n")
	cl, err := s.smtpConnect(host, port, user, pass, security)
	if err != nil {
		return err
	}
	defer cl.Close()
	return s.smtpSendMsg(cl, user, pass, host, from, to, msg)
}
