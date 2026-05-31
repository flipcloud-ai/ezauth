package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CreateTestCertificates creates temporary SSL certificates for testing
// Returns paths to: caCertPath, clientCertPath, clientKeyPath
func CreateTestCertificates() (string, string, string) {
	tempDir, err := os.MkdirTemp("", "pgx-test-certs-*")
	if err != nil {
		return "", "", ""
	}

	// Generate CA key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", ""
	}

	// Create CA certificate
	caCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caCertTemplate, &caCertTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", ""
	}
	caCertPath := filepath.Join(tempDir, "ca.crt")
	if err := os.WriteFile(caCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}), 0o600); err != nil {
		return "", "", ""
	}

	// Generate client key
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", ""
	}
	clientKeyPath := filepath.Join(tempDir, "client.key")
	clientKeyBytes := x509.MarshalPKCS1PrivateKey(clientKey)
	if err := os.WriteFile(clientKeyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: clientKeyBytes}), 0600); err != nil {
		return "", "", ""
	}

	// Create client certificate
	clientCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientCertTemplate, &caCertTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return "", "", ""
	}
	clientCertPath := filepath.Join(tempDir, "client.crt")
	if err := os.WriteFile(clientCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER}), 0o600); err != nil {
		return "", "", ""
	}

	_ = fmt.Sprintf("created certs in %s", tempDir)
	return caCertPath, clientCertPath, clientKeyPath
}
