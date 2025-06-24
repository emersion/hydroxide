package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func TLS(certPath string, keyPath string, clientCAPath string) (*tls.Config, error) {
	var tlsConfig *tls.Config

	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("unable load key pair: %s", err)
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	if clientCAPath != "" {
		if tlsConfig == nil {
			return nil, fmt.Errorf("cannot check client certificate without a server certificate and key")
		}

		data, err := ioutil.ReadFile(clientCAPath)
		if err != nil {
			return nil, fmt.Errorf("unable read CA file: %s", err)
		}

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(data)

		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

// GenerateSelfSignedCert generates a self-signed certificate and key for local use
func GenerateSelfSignedCert(certPath, keyPath string) error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Hydroxide"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("failed to create key directory: %v", err)
	}

	// Write certificate file
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	// Write private key file
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer keyOut.Close()

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(keyOut, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	// Set appropriate permissions on key file
	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("failed to set key file permissions: %v", err)
	}

	return nil
}

// TLSWithAutoGenerate handles TLS configuration with optional auto-generation of certificates
func TLSWithAutoGenerate(certPath string, keyPath string, clientCAPath string, autoGenerate bool) (*tls.Config, error) {
	if autoGenerate && (certPath == "" || keyPath == "") {
		// Use default paths in config directory
		configHome, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get config directory: %v", err)
		}
		configDir := filepath.Join(configHome, "hydroxide")
		
		if certPath == "" {
			certPath = filepath.Join(configDir, "hydroxide.crt")
		}
		if keyPath == "" {
			keyPath = filepath.Join(configDir, "hydroxide.key")
		}
	}

	// Check if we need to generate certificates
	if autoGenerate {
		_, certErr := os.Stat(certPath)
		_, keyErr := os.Stat(keyPath)
		
		if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
			if err := GenerateSelfSignedCert(certPath, keyPath); err != nil {
				return nil, fmt.Errorf("failed to generate self-signed certificate: %v", err)
			}
		}
	}

	return TLS(certPath, keyPath, clientCAPath)
}
