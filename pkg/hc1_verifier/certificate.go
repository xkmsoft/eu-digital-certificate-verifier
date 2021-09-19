package hc1_verifier

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	cose "github.com/veraison/go-cose"
	"io"
	"net/http"
)

const (
	TrustURL         = "https://hc1_verifier-api.coronacheck.nl/v4/hc1_verifier/public_keys"
	ContextSignature = "Signature1"
)

// AvailableAlgorithms The algorithms defined in this document can be found in Table 1.
//              +=======+=======+=========+==================+
//              | Name  | Value | Hash    | Description      |
//              +=======+=======+=========+==================+
//              | ES256 | -7    | SHA-256 | ECDSA w/ SHA-256 |
//              +-------+-------+---------+------------------+
//              | ES384 | -35   | SHA-384 | ECDSA w/ SHA-384 |
//              +-------+-------+---------+------------------+
//              | ES512 | -36   | SHA-512 | ECDSA w/ SHA-512 |
//              +-------+-------+---------+------------------+
//
//                     Table 1: ECDSA Algorithm Values
var AvailableAlgorithms = map[int]*cose.Algorithm{
	-7:  cose.ES256,
	-35: cose.ES384,
	-36: cose.ES256,
}

// SigningHeader
// 2.6.2 Signing Header
//   The header of COSE contains the used algorithm and the key identifier:
//
//   Name    CBOR Major Type    Placement In Header    Type    Value                             Description
//   alg     1                  protected              nint    -7/-37 (ES256)                    Algorithm Field
//   kid     4                  protected              array   First 8 bytes of the hash value   KeyIdentifiers Field
type SigningHeader struct {
	Algorithm      int    `cbor:"1,keyasint,omitempty"`
	KeyIdentifiers []byte `cbor:"4,keyasint,omitempty"`
}

// SignedCWT https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-certificates_v3_en.pdf
// 2.6.1 COSE Structure
//   A COSE structure contains a protected, unprotected and payload object within one CBOR array defined in the Basic Structure of the RFC81527
//
//     Name        CBOR Major Type      Type
//     Protected   2                    bstr
//     Payload     2                    bstr
//     Signature   2                    bstr
//     Unprotected 2                    empty
type SignedCWT struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
	Payload     []byte
	Signature   []byte
}

// HealthCertificate simply keeps the DGC which is CovidCertificate
type HealthCertificate struct {
	DigitalGreenCertificate CovidCertificate `cbor:"1,keyasint"`
}

// CovidCertificate https://ec.europa.eu/health/sites/default/files/ehealth/docs/covid-certificate_json_specification_en.pdf
type CovidCertificate struct {
	Version         string           `cbor:"ver" json:"ver"`
	PersonalName    Name             `cbor:"nam" json:"nam"`
	DateOfBirth     string           `cbor:"dob" json:"dob"`
	VaccineRecords  []VaccineRecord  `cbor:"v" json:"v,omitempty"`
	TestRecords     []TestRecord     `cbor:"t" json:"t,omitempty"`
	RecoveryRecords []RecoveryRecord `cbor:"r" json:"r,omitempty"`
}

// Name https://ec.europa.eu/health/sites/default/files/ehealth/docs/covid-certificate_json_specification_en.pdf
// Section: Person name and date of birth: Person name is the official full name of the person, matching the name stated on travel documents. The
// identifier of the structure is nam. Exactly 1 (one) person name MUST be provided.
type Name struct {
	FamilyName    string `cbor:"fn" json:"fn"`
	FamilyNameStd string `cbor:"fnt" json:"fnt"`
	GivenName     string `cbor:"gn" json:"gn"`
	GivenNameStd  string `cbor:"gnt" json:"gnt"`
}

// VaccineRecord https://ec.europa.eu/health/sites/default/files/ehealth/docs/covid-certificate_json_specification_en.pdf
// Section: Certificate type specific information - Vaccination certificate:
// Vaccination group, if present, MUST contain exactly 1 (one) entry describing exactly one vaccination
// event. All elements of the vaccination group are mandatory, empty values are not supported.
type VaccineRecord struct {
	Target        string  `cbor:"tg" json:"tg"`
	Vaccine       string  `cbor:"vp" json:"vp"`
	Product       string  `cbor:"mp" json:"mp"`
	Manufacturer  string  `cbor:"ma" json:"ma"`
	Doses         float64 `cbor:"dn" json:"dn"`
	DoseSeries    float64 `cbor:"sd" json:"sd"`
	Date          string  `cbor:"dt" json:"dt"`
	Country       string  `cbor:"co" json:"co"`
	Issuer        string  `cbor:"is" json:"is"`
	CertificateID string  `cbor:"ci" json:"ci"`
}

// TestRecord https://ec.europa.eu/health/sites/default/files/ehealth/docs/covid-certificate_json_specification_en.pdf
// Section: Test certificate: Test group, if present, MUST contain exactly 1 (one) entry describing exactly one test result.
type TestRecord struct {
	Target         string `cbor:"tg" json:"tg"`
	TestType       string `cbor:"tt" json:"tt"`
	Name           string `cbor:"nm" json:"nm"`
	Manufacturer   string `cbor:"ma" json:"ma"`
	SampleDatetime string `cbor:"sc" json:"sc"`
	TestResult     string `cbor:"tr" json:"tr"`
	TestingCentre  string `cbor:"tc" json:"tc"`
	Country        string `cbor:"co" json:"co"`
	Issuer         string `cbor:"is" json:"is"`
	CertificateID  string `cbor:"ci" json:"ci"`
}

// RecoveryRecord https://ec.europa.eu/health/sites/default/files/ehealth/docs/covid-certificate_json_specification_en.pdf
// Section: Recovery certificate: Recovery group, if present, MUST contain exactly 1 (one) entry describing exactly one recovery
// statement. All elements of the recovery group are mandatory, empty values are not supported.
type RecoveryRecord struct {
	Target            string `cbor:"tg" json:"tg"`
	Country           string `cbor:"co" json:"co"`
	Issuer            string `cbor:"is" json:"is"`
	FirstPositiveTest string `cbor:"fr" json:"fr"`
	ValidFrom         string `cbor:"df" json:"df"`
	ValidUntil        string `cbor:"du" json:"du"`
	CertificateID     string `cbor:"ci" json:"ci"`
}

// CWTClaims
//  3.3 CWT CWTClaims
//    3.3.1 CWT Structure Overview
//      • Protected	Header
//      • Signature	Algorithm (alg, label 1)
//      • Key Identifier (kid, label 4)
//      • Payload
//      • Issuer (iss, claim key 1, optional, ISO 3166-1 alpha-2 of issuer)
//      • IssuedAt	(iat, claim	key	6)
//      • ExpirationTime (exp, claim key 4)
//      • HealthCertificate (hcert, claim key -260)
//      – EU Digital Green Certificate v1 (eu_dgc_v1, claim	key	1)
//      • Signature
type CWTClaims struct {
	Issuer            string            `cbor:"1,keyasint"`
	ExpirationTime    int64             `cbor:"4,keyasint"`
	IssuedAt          int64             `cbor:"6,keyasint"`
	HealthCertificate HealthCertificate `cbor:"-260,keyasint"`
}

// DGC The general structure to keep SignedCWT, SigningHeader, CWTClaims, Cert and PublicKey
type DGC struct {
	V         SignedCWT
	P         SigningHeader
	Claims    CWTClaims
	Cert      *x509.Certificate
	PublicKey *crypto.PublicKey
}

// TrustURLStruct is the initial JSON struct returned from the trusted list GET request
type TrustURLStruct struct {
	Signature string `json:"signature"`
	Payload   string `json:"payload"`
}

// TrustURLPayload is the Payload field of TrustURLStruct
type TrustURLPayload struct {
	CLKeys []CLKeyStruct            `json:"cl_keys"`
	EUKeys map[string][]EUKeyStruct `json:"eu_keys"`
}

// CLKeyStruct is the CLKeys field of TrustURLPayload
type CLKeyStruct struct {
	Id        string `json:"id"`
	PublicKey string `json:"public_key"`
}

// EUKeyStruct is the EUKeys field of TrustURLPayload
type EUKeyStruct struct {
	SubjectPublicKey string   `json:"subjectPk"`
	Ian              string   `json:"ian"`
	San              string   `json:"san"`
	KeyUsage         []string `json:"key_usage"`
}

// GetPublicKey tries to find the public key of certificate from the trusted list using the country code (Issuer)
// and the KID (key identifier)
func (d *DGC) GetPublicKey(countryCode string, keyIdentifier []byte) (crypto.PublicKey, error) {
	kidKey := base64.StdEncoding.EncodeToString(keyIdentifier)
	fmt.Printf("Country code  : %s\n", countryCode)
	fmt.Printf("Key identifier: %s\n", base64.StdEncoding.EncodeToString(keyIdentifier))

	resp, err := http.Get(TrustURL)
	if err != nil {
		return nil, fmt.Errorf("error requesting GET: %s\n", err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %s\n", err.Error())
	}
	var trustUrlStruct TrustURLStruct
	if err := json.Unmarshal(body, &trustUrlStruct); err != nil {
		return nil, fmt.Errorf("error unmarshalling trusted urls: %s\n", err.Error())
	}
	payload, err := base64.StdEncoding.DecodeString(trustUrlStruct.Payload)
	if err != nil {
		return nil, fmt.Errorf("error decoding payload of trusted urls: %s\n", err.Error())
	}
	var trustUrlPayload TrustURLPayload
	if err := json.Unmarshal(payload, &trustUrlPayload); err != nil {
		return nil, fmt.Errorf("error unmarhsalling trusted urls payload: %s\n", err.Error())
	}
	countryKeys, ok := trustUrlPayload.EUKeys[kidKey]
	if !ok {
		return nil, fmt.Errorf("key identifier %s could not be found in the trust list\n", kidKey)
	}
	for _, countryKey := range countryKeys {
		if countryKey.Ian == countryCode {
			// Same key identifier and country code
			der, err := base64.StdEncoding.DecodeString(countryKey.SubjectPublicKey)
			if err != nil {
				return nil, fmt.Errorf("%s public key found but could not be decoded: %s\n", countryCode, err.Error())
			}
			publicKey, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				return nil, fmt.Errorf("error parsing public key der form: %s\n", err)
			}
			return publicKey, nil
		}
	}
	return nil, fmt.Errorf("public key for country %s and key identifier %s could not be found\n", countryCode, kidKey)
}

// GetDigest creates the digest with provided toToSigned data and algorithm
func (d *DGC) GetDigest(toBeSigned []byte, algorithm *cose.Algorithm) ([]byte, error) {
	if !algorithm.HashFunc.Available() {
		return nil, fmt.Errorf("hash function is not available for algorithm: %s\n", algorithm.Name)
	}
	hasher := algorithm.HashFunc.New()
	if _, err := hasher.Write(toBeSigned); err != nil {
		return nil, fmt.Errorf("hasher function failed to write the data to be signed: %s\n", err.Error())
	}
	return hasher.Sum(nil), nil
}

// CreateSigStructure creates the sig structure to be signed by the algorithm hasher
// 4.4.  Signing and Verification Process
//
//   In order to create a signature, a well-defined byte stream is needed.
//   The Sig_structure is used to create the canonical form.  This signing
//   and verification process takes in the body information (COSE_Sign or
//   COSE_Sign1), the signer information (COSE_Signature), and the
//   application data (external source).  A Sig_structure is a CBOR array.
//   The fields of the Sig_structure in order are:
//
//   1.  A text string identifying the context of the signature.  The
//       context string is:
//
//          "Signature" for signatures using the COSE_Signature structure.
//          "Signature1" for signatures using the COSE_Sign1 structure.
//          "CounterSignature" for signatures used as counter signature
//          attributes.
//
//   2.  The protected attributes from the body structure encoded in a
//       bstr type.  If there are no protected attributes, a bstr of
//       length zero is used.
//
//   3.  The protected attributes from the signer structure encoded in a
//       bstr type.  If there are no protected attributes, a bstr of
//       length zero is used.  This field is omitted for the COSE_Sign1
//       signature structure.
//   4.  The protected attributes from the application encoded in a bstr
//       type.  If this field is not supplied, it defaults to a zero-
//       length binary string.  (See Section 4.3 for application guidance
//       on constructing this field.)
//
//   5.  The payload to be signed encoded in a bstr type.  The payload is
//       placed here independent of how it is transported.
//
//   The CDDL fragment that describes the above text is:
//
//   Sig_structure = [
//       context : "Signature" / "Signature1" / "CounterSignature",
//       body_protected : empty_or_serialized_map,
//       ? sign_protected : empty_or_serialized_map,
//       external_aad : bstr,
//       payload : bstr
//   ]
func (d *DGC) CreateSigStructure() ([]byte, error) {
	toBeSigned, err := cose.Marshal([]interface{}{
		ContextSignature,
		d.V.Protected,
		[]byte{},
		d.V.Payload,
	})
	if err != nil {
		return nil, errors.Errorf("Error marshaling structure: %s", err)
	}
	return toBeSigned, nil
}

// Verify verifies the certificate against its kid and country code (Issuer) from the trusted urls.
// if there is a match the public key is returned and the certificate is verified with its digest and signature
func (d *DGC) Verify() (bool, error) {
	keyIdentifier := d.P.KeyIdentifiers
	if len(keyIdentifier) == 0 {
		if b, ok := d.V.Unprotected[uint64(4)]; ok {
			keyIdentifier = b.([]byte)
		} else {
			return false, fmt.Errorf("failed to retrieve the key identifier")
		}
	}
	algorithm := d.P.Algorithm
	if algorithm == 0 {
		if b, ok := d.V.Unprotected[uint64(1)]; ok {
			algorithm = int(b.(int64))
		} else {
			return false, fmt.Errorf("failed to retrieve the algorithm")
		}
	}
	publicKey, err := d.GetPublicKey(d.Claims.Issuer, keyIdentifier)
	if err != nil {
		return false, err
	}
	alg, ok := AvailableAlgorithms[algorithm]
	if !ok {
		return false, fmt.Errorf("unsupported algorithm: %d\n", algorithm)
	}
	verifier := &cose.Verifier{
		PublicKey: publicKey,
		Alg:       alg,
	}
	toBeSigned, err := d.CreateSigStructure()
	if err != nil {
		return false, err
	}
	digest, err := d.GetDigest(toBeSigned, alg)
	if err != nil {
		return false, err
	}
	if err := verifier.Verify(digest, d.V.Signature); err != nil {
		return false, fmt.Errorf("signature could not be verified: %s\n", err.Error())
	}
	fmt.Printf("Correct signature against known key identifier %s (%s)\n", base64.StdEncoding.EncodeToString(keyIdentifier), d.Claims.Issuer)
	d.PublicKey = &publicKey
	return true, nil
}

// VerifyWithCertificate test files' key identifiers mostly does not exist in the trusted lists. They are provided
// with their own certificates. This function verifies a test certificate with provided certificate
func (d *DGC) VerifyWithCertificate(certificate *x509.Certificate) (bool, error) {
	algorithm := d.P.Algorithm
	if algorithm == 0 {
		if b, ok := d.V.Unprotected[uint64(1)]; ok {
			algorithm = int(b.(int64))
		} else {
			return false, fmt.Errorf("failed to retrieve the algorithm")
		}
	}
	publicKey := certificate.PublicKey
	alg, ok := AvailableAlgorithms[algorithm]
	if !ok {
		return false, fmt.Errorf("unsupported algorithm: %d\n", algorithm)
	}
	verifier := &cose.Verifier{
		PublicKey: publicKey,
		Alg:       alg,
	}
	toBeSigned, err := d.CreateSigStructure()
	if err != nil {
		return false, err
	}
	digest, err := d.GetDigest(toBeSigned, alg)
	if err != nil {
		return false, err
	}
	if err := verifier.Verify(digest, d.V.Signature); err != nil {
		return false, fmt.Errorf("signature could not be verified: %s\n", err.Error())
	}
	d.Cert = certificate
	return true, nil
}

// ToJSONCertificate simply returns well indented json string of the DGC
func (d *DGC) ToJSONCertificate() (string, error) {
	bytes, err := json.MarshalIndent(d.Claims.HealthCertificate.DigitalGreenCertificate, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error marhsalling digital green certificate: %s\n", err.Error())
	}
	return string(bytes), nil
}
