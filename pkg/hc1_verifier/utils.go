package hc1_verifier

import (
	"bytes"
	"compress/zlib"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

// ZlibDecompress simply decompressed the input and returns the decompressed []byte
func ZlibDecompress(input []byte) ([]byte, error) {
	var in bytes.Buffer
	if _, err := in.Write(input); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	r, err := zlib.NewReader(&in)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(&buffer, r); err != nil {
		return nil, err
	}
	if err := r.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// CreateCertificateFromPEM simply creates x509.Certificate from the PEM string
// TESTCTX -> CERTIFICATE field of a given test file
func CreateCertificateFromPEM(data string) (*x509.Certificate, error) {
	pemString := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", data)
	block, _ := pem.Decode([]byte(pemString))
	if block == nil  {
		return nil, fmt.Errorf("failed to decode the PEM block")
	}
	publicCertificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the certificate")
	}
	return publicCertificate, nil

}