package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

func TLS(certPath string, keyPath string, clientCAPath string) (*tls.Config, error) {

	tlsConfig := &tls.Config{}

	if certPath != "" && keyPath != "" {

		certData, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("error: unable read certificate: %s", err)
		}

		keyData, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("error: unable read key: %s", err)
		}

		cert, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			return nil, fmt.Errorf("error: unable load key pair: %s", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if clientCAPath != "" {

		data, err := ioutil.ReadFile(clientCAPath)
		if err != nil {
			return nil, fmt.Errorf("error: unable read CA file: %s", err)
		}

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(data)

		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}
