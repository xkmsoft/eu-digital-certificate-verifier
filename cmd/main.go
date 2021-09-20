package main

import (
	"encoding/json"
	"fmt"
	"github.com/xkmsoft/eu-digital-certificate-verifier/pkg/hc1_verifier"
	"io"
	"log"
	"net/http"
)

// TestFile is the JSON structure of defined test files on https://github.com/eu-digital-green-certificates/dgc-testdata
type TestFile struct {
	JSON struct {
		Ver string `json:"ver"`
		Nam struct {
			Fn  string `json:"fn"`
			Fnt string `json:"fnt"`
			Gn  string `json:"gn"`
			Gnt string `json:"gnt"`
		} `json:"nam"`
		Dob string `json:"dob"`
		V   []struct {
			Tg string `json:"tg"`
			Vp string `json:"vp"`
			Mp string `json:"mp"`
			Ma string `json:"ma"`
			Dn int    `json:"dn"`
			Sd int    `json:"sd"`
			Dt string `json:"dt"`
			Co string `json:"co"`
			Is string `json:"is"`
			Ci string `json:"ci"`
		} `json:"v"`
	} `json:"JSON"`
	CBOR       string `json:"CBOR"`
	COSE       string `json:"COSE"`
	COMPRESSED string `json:"COMPRESSED"`
	BASE45     string `json:"BASE45"`
	PREFIX     string `json:"PREFIX"`
	DCODE      string `json:"2DCODE"`
	TESTCTX    struct {
		VERSION         int    `json:"VERSION"`
		SCHEMA          string `json:"SCHEMA"`
		CERTIFICATE     string `json:"CERTIFICATE"`
		VALIDATIONCLOCK string `json:"VALIDATIONCLOCK"`
		DESCRIPTION     string `json:"DESCRIPTION"`
	} `json:"TESTCTX"`
	EXPECTEDRESULTS struct {
		EXPECTEDVALIDOBJECT      bool `json:"EXPECTEDVALIDOBJECT"`
		EXPECTEDSCHEMAVALIDATION bool `json:"EXPECTEDSCHEMAVALIDATION"`
		EXPECTEDENCODE           bool `json:"EXPECTEDENCODE"`
		EXPECTEDDECODE           bool `json:"EXPECTEDDECODE"`
		EXPECTEDVERIFY           bool `json:"EXPECTEDVERIFY"`
		EXPECTEDCOMPRESSION      bool `json:"EXPECTEDCOMPRESSION"`
		EXPECTEDKEYUSAGE         bool `json:"EXPECTEDKEYUSAGE"`
		EXPECTEDUNPREFIX         bool `json:"EXPECTEDUNPREFIX"`
		EXPECTEDVALIDJSON        bool `json:"EXPECTEDVALIDJSON"`
		EXPECTEDB45DECODE        bool `json:"EXPECTEDB45DECODE"`
		EXPECTEDPICTUREDECODE    bool `json:"EXPECTEDPICTUREDECODE"`
		EXPECTEDEXPIRATIONCHECK  bool `json:"EXPECTEDEXPIRATIONCHECK"`
	} `json:"EXPECTEDRESULTS"`
}

// FetchTestFile simply fetches the test file of the given url and returns the TestFile structure
func FetchTestFile(url string) (*TestFile, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error requesting GET: %s\n", err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %s\n", err.Error())
	}
	var testFile TestFile
	if err := json.Unmarshal(body, &testFile); err != nil {
		return nil, fmt.Errorf("error unmarshalling test file: %s\n", err.Error())
	}
	return &testFile, nil
}

func main() {
	url := "https://raw.githubusercontent.com/eu-digital-green-certificates/dgc-testdata/main/GR/2DCode/raw/1.json"
	testFile, err := FetchTestFile(url)
	if err != nil {
		log.Fatal(err)
	}
	certificate, err := hc1_verifier.CreateCertificateFromPEM(testFile.TESTCTX.CERTIFICATE)
	if err != nil {
		log.Fatal(err)
	}
	dgc, err := hc1_verifier.VerifyWithCertificate(testFile.PREFIX, certificate)
	if err != nil {
		log.Fatal(err)
	}
	claims, err := dgc.ToJSONClaims()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Verified health certificate: %s\n", claims)
}
