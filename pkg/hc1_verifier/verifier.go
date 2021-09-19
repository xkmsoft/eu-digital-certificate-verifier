package hc1_verifier

import (
	"crypto/x509"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"github.com/xkmsoft/base45"
	"strings"
)

const (
	HealthCertificatePrefix = "HC1:"
	ZlibMagicNumber         = 0x78
)

// ValidateAndRemovePrefix simply checks if QR code has a prefix "HC1:"
// and returns trimmed qr code (without prefix)
func ValidateAndRemovePrefix(in string) (string, error) {
	if strings.HasPrefix(in, HealthCertificatePrefix) {
		trimmed := strings.TrimPrefix(in, HealthCertificatePrefix)
		return trimmed, nil
	}
	return "", fmt.Errorf("prefix %s could not be found\n", HealthCertificatePrefix)
}

// DecodeCOSE simply decodes the coseData and returns DGC without CERT and PublicKey fields.
// These fields are populated once the DGC is verified
func DecodeCOSE(coseData []byte) (*DGC, error) {
	var v SignedCWT
	if err := cbor.Unmarshal(coseData, &v); err != nil {
		return nil, err
	}

	var p SigningHeader
	if len(v.Protected) > 0 {
		if err := cbor.Unmarshal(v.Protected, &p); err != nil {
			return nil, err
		}
	}

	var c CWTClaims
	if err := cbor.Unmarshal(v.Payload, &c); err != nil {
		return nil, err
	}

	return &DGC{
		V:         v,
		P:         p,
		Claims:    c,
		Cert:      nil,
		PublicKey: nil,
	}, nil
}

// Verify applies the following algorithm to create verified DGC
//  1. Prefix validation
//  2. Base45 decoding
//  3. ZLIB decompression
//  4. Decoding the CBOR data
//  5. Verification with KID against the trusted list database
//     - Extracting the KID and Issuer (country code)
//     - Searching the KID and country code in the trusted list database
//     - Creating digest of the certificate using the algorithm of the certificate
//     - Verifying the certificate using its digest and signature
func Verify(qrCode string) (*DGC, error) {
	// Phase1: Prefix validation
	validated, err := ValidateAndRemovePrefix(qrCode)
	if err != nil {
		return nil, fmt.Errorf("prexif validation error: %s\n", err.Error())
	}
	// Phase2: Base45 Decoding
	decoded, err := base45.Decode(validated)
	if err != nil {
		return nil, fmt.Errorf("base45 decoding error: %s\n", err.Error())
	}
	cborData := []byte(decoded)
	if cborData[0] == ZlibMagicNumber {
		// Phase 3: ZLIB decompression
		decompressed, err := ZlibDecompress(cborData)
		if err != nil {
			return nil, fmt.Errorf("zlib decompression error: %s\n", err.Error())
		}
		cborData = decompressed
	}
	// Phase 4: Decoding the CBOR data
	dgc, err := DecodeCOSE(cborData)
	if err != nil {
		return nil, err
	}
	// Phase 5: Verifying the certificate with its key identifiers using the trusted list
	verified, err := dgc.Verify()
	if err != nil {
		return nil, err
	}
	if verified {
		return dgc, nil
	}
	return nil, fmt.Errorf("certificate could not be verified\n")
}

// VerifyWithCertificate applies the following algorithm to create verified DGC
//  1. Prefix validation
//  2. Base45 decoding
//  3. ZLIB decompression
//  4. Decoding the CBOR data
//  5. Verification with provided certificate parameter
//     - Creating digest of the certificate using the algorithm of the certificate
//     - Verifying the certificate using its digest and signature
func VerifyWithCertificate(qrCode string, certificate *x509.Certificate) (*DGC, error) {
	// Phase1: Prefix validation
	validated, err := ValidateAndRemovePrefix(qrCode)
	if err != nil {
		return nil, fmt.Errorf("prexif validation error: %s\n", err.Error())
	}
	// Phase2: Base45 Decoding
	decoded, err := base45.Decode(validated)
	if err != nil {
		return nil, fmt.Errorf("base45 decoding error: %s\n", err.Error())
	}
	cborData := []byte(decoded)
	if cborData[0] == ZlibMagicNumber {
		// Phase 3: ZLIB decompression
		decompressed, err := ZlibDecompress(cborData)
		if err != nil {
			return nil, fmt.Errorf("zlib decompression error: %s\n", err.Error())
		}
		cborData = decompressed
	}
	// Phase 4: Decoding the CBOR data
	dgc, err := DecodeCOSE(cborData)
	if err != nil {
		return nil, err
	}
	// Phase 5: Verifying the certificate with provided certificate (for test files)
	verified, err := dgc.VerifyWithCertificate(certificate)
	if err != nil {
		return nil, err
	}
	if verified {
		fmt.Printf("Certificate is verified successfully\n")
		return dgc, nil
	}
	return nil, fmt.Errorf("certificate could not be verified\n")
}
