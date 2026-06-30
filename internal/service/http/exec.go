package http

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type ExecClaims struct {
	Command string `json:"command"`
	jwt.RegisteredClaims
}

func (s *Service) execHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.args.ExecPublicKey == "" {
		http.Error(w, "Exec feature disabled: public key not configured", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	tokenString := strings.TrimSpace(string(body))

	block, _ := pem.Decode([]byte(s.args.ExecPublicKey))
	if block == nil {
		http.Error(w, "Invalid PEM format in config", http.StatusInternalServerError)
		return
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		http.Error(w, "Failed to parse public key", http.StatusInternalServerError)
		return
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		http.Error(w, "Configured key is not ECDSA", http.StatusInternalServerError)
		return
	}

	claims := &ExecClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ecdsaPub, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid or unauthorized token", http.StatusUnauthorized)
		return
	}

	if strings.TrimSpace(claims.Command) == "" {
		http.Error(w, "Empty command", http.StatusBadRequest)
		return
	}

	cmd := exec.Command(claims.Command)
	output, err := cmd.CombinedOutput()
	
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("Command failed: %v\nOutput: %s", err, string(output))))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(output)
}
