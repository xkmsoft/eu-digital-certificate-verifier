### EU Digital Certificate Verifier written in Go

This library is a basic implementation of verification process of the EU digital health certificates defined on [https://ec.europa.eu/health/ehealth/covid-19_en](https://ec.europa.eu/health/ehealth/covid-19_en) and the official repository [https://github.com/eu-digital-green-certificates](https://github.com/eu-digital-green-certificates)

### Sample usage

The following test file is used [https://github.com/eu-digital-green-certificates/dgc-testdata/blob/main/GR/2DCode/raw/1.json](https://github.com/eu-digital-green-certificates/dgc-testdata/blob/main/GR/2DCode/raw/1.json)

```json
{
    "JSON": {
        "ver": "1.0.0",
        "nam": {
            "fn": "ΜΕΝΕΞΕΣ",
            "fnt": "MENEXES",
            "gn": "ΜΑΡΙΟΣ",
            "gnt": "MARIOS"
        },
        "dob": "1980-11-11",
        "v": [
            {
                "tg": "840539006",
                "vp": "1119349007",
                "mp": "EU/1/20/1528",
                "ma": "ORG-100030215",
                "dn": 2,
                "sd": 2,
                "dt": "2021-02-19",
                "co": "GR",
                "is": "IDIKA / Ministry of Digital Governance",
                "ci": "URN:UVCI:01:GR:7UXL2ZTSS6KUZAF2XAAA3A4C4I#E"
            }
        ]
    },
    "CBOR": "a4061a60bc9b1c041a645df85101624752390103a101a46376657265312e302e30636e616da462666e6ece9cce95ce9dce95ce9ece95cea363666e74674d454e4558455362676e6cce9cce91cea1ce99ce9fcea363676e74664d4152494f5363646f626a313938302d31312d3131617681aa627467693834303533393030366276706a31313139333439303037626d706c45552f312f32302f31353238626d616d4f52472d31303030333032313562646e02627364026264746a323032312d30322d313962636f62475262697378264944494b41202f204d696e6973747279206f66204469676974616c20476f7665726e616e6365626369782b55524e3a555643493a30313a47523a3755584c325a545353364b555a414632584141413341344334492345",
    "COSE": "d28450a3012603183d0448bb1be5f9db32ac1ca0590125a4061a60bc9b1c041a645df85101624752390103a101a46376657265312e302e30636e616da462666e6ece9cce95ce9dce95ce9ece95cea363666e74674d454e4558455362676e6cce9cce91cea1ce99ce9fcea363676e74664d4152494f5363646f626a313938302d31312d3131617681aa627467693834303533393030366276706a31313139333439303037626d706c45552f312f32302f31353238626d616d4f52472d31303030333032313562646e02627364026264746a323032312d30322d313962636f62475262697378264944494b41202f204d696e6973747279206f66204469676974616c20476f7665726e616e6365626369782b55524e3a555643493a30313a47523a3755584c325a545353364b555a4146325841414133413443344923455840e8b57700be1a410b0cc896e8be57075f8ba54cefcba0de51c0185f4168487b92fbbdf4bc7732948db6b263ec517db5ca297ad05d2a953fa328305c64f41c04a7",
    "COMPRESSED": "78dabbd412b098518d59c296c563b7f4d39fb78dd6c82c8864545dc22695b067b60c8b544aec8f40c624f7204b46e6858c4b92cb528b520df50cf40c92f312739724a5e5e59d9b736eeab9b9403c0f881727a7e595a4fbbafab946b80627a5e7e50065279e5b786ee6b9f940b9f4bc92345fc7204fffe0e494fca42c434b0b035d4343204a2c6b5c9554929e696162606a6c6960609654569065686868696c02e49927e516e4b886ea1bea1b19e81b9a1a5924e526e6fa07b9eb1a1a1818181b18199a26a5e4312515a73025a59464190105740d8c740d2d9392f3810e4fca2cae50f374f1f47654d057f0cdcccb2c2e29aa54c84f5370c94ccf2c49cc5170cf077a2a2f312f39352939b3423b34c8cf2a34ccd9d3cac0d0ca3dc8ca3c34c2c7282a2438d8cc3b34cad1cd28c2d1d1d1d8d1c4d9c453d935c2e1c5d672867d528edc3c27a6bdd817ce1edfbdd4e7fde905f7020f48c43b6678544ffabdf7cb9e72a329bddb3625bf09acdd7a4ab3ea42acd654fbc51a0631295f645896030036468d98",
    "BASE45": "NCFOXNEG2NBJ5*H:QO-.OMBN+XQ99N*6RFS5YUCH%BM*4ODMT0NSRHAL9.4I92P*AVAN9I6T5XH4PIQJAZGA2:UG%U:PI/E2$4JY/KB1TFTJ:0EPLNJ58G/1W-26ALD-I2$VFVVE.80Z0 /KY.SKZC*0K5AFP7T/MV*MNY$N.R6 7P45AHJSP$I/XK$M8TH1PZB*L8/G9YPDN*I4OIMEDTJCJKDLEDL9CZTAKBI/8D:8DKTDL+S/15A+2XEN QT QTHC31M3+E3+T4D-4HRVUMNMD3323623423.LJX/KQ968X2+36/-KKTC 509UE1YH/T1NTICZUI 16PPT1M:YUKQU7/EAFQ+JU2+PFQ51C5EWAC1ASBE/V9.Q5F$PYBEO.0:E5 96KA7N95ZTM L7HHP4F5G+P%YQ+GONPPCHPMR73SOM352Q4FIR L7 SP5.PDSOSNQKIR%*O* OUKRTSOL0PNLE.$FW2I9R7P3LEERQ2Q$CS8-QL4W.X0WB0/89-M7O9F:4AV0OGXP7MEKC53WRXY41A1/:R/J9URTB%LKXAD-OAZ0GA5%UCI/I910G-8H3",
    "PREFIX": "HC1:NCFOXNEG2NBJ5*H:QO-.OMBN+XQ99N*6RFS5YUCH%BM*4ODMT0NSRHAL9.4I92P*AVAN9I6T5XH4PIQJAZGA2:UG%U:PI/E2$4JY/KB1TFTJ:0EPLNJ58G/1W-26ALD-I2$VFVVE.80Z0 /KY.SKZC*0K5AFP7T/MV*MNY$N.R6 7P45AHJSP$I/XK$M8TH1PZB*L8/G9YPDN*I4OIMEDTJCJKDLEDL9CZTAKBI/8D:8DKTDL+S/15A+2XEN QT QTHC31M3+E3+T4D-4HRVUMNMD3323623423.LJX/KQ968X2+36/-KKTC 509UE1YH/T1NTICZUI 16PPT1M:YUKQU7/EAFQ+JU2+PFQ51C5EWAC1ASBE/V9.Q5F$PYBEO.0:E5 96KA7N95ZTM L7HHP4F5G+P%YQ+GONPPCHPMR73SOM352Q4FIR L7 SP5.PDSOSNQKIR%*O* OUKRTSOL0PNLE.$FW2I9R7P3LEERQ2Q$CS8-QL4W.X0WB0/89-M7O9F:4AV0OGXP7MEKC53WRXY41A1/:R/J9URTB%LKXAD-OAZ0GA5%UCI/I910G-8H3",
    "2DCODE": "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",
    "TESTCTX": {
        "VERSION": 1,
        "SCHEMA": "1.0.0",
        "CERTIFICATE": "MIIBzDCCAXGgAwIBAgIUDN8nWnn8gBmlWgL3stwhoinVD5MwCgYIKoZIzj0EAwIwIDELMAkGA1UEBhMCR1IxETAPBgNVBAMMCGdybmV0LmdyMB4XDTIxMDUxMjExMjY1OFoXDTIzMDUxMjExMjY1OFowIDELMAkGA1UEBhMCR1IxETAPBgNVBAMMCGdybmV0LmdyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBcc6ApRZrh9/qCuMnxIRpUujI19bKkG+agj/6rPOiX8VyzfWvhptzV0149AFRWdSoF/NVuQyFcrBoNBqL9zCAqOBiDCBhTAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFN6ZiC57J/yRqTJ/Tg2eRspLCHDhMB8GA1UdIwQYMBaAFNU5HfWNY37TbdZjvsvO+1y1LPJYMDMGA1UdJQQsMCoGDCsGAQQBAI43j2UBAQYMKwYBBAEAjjePZQECBgwrBgEEAQCON49lAQMwCgYIKoZIzj0EAwIDSQAwRgIhAN6rDdE4mtTt2ZuffpZ242/B0lmyvdd+Wy6VuX+J/b01AiEAvME52Y4zqkQDuj2kbfCfs+h3uwYFOepoBP14X+Rd/VM=",
        "VALIDATIONCLOCK": "2021-06-08T15:56:26.670297",
        "DESCRIPTION": "VALID: EC 256 key"
    },
    "EXPECTEDRESULTS": {
        "EXPECTEDVALIDOBJECT": true,
        "EXPECTEDSCHEMAVALIDATION": true,
        "EXPECTEDENCODE": true,
        "EXPECTEDDECODE": true,
        "EXPECTEDVERIFY": true,
        "EXPECTEDCOMPRESSION": true,
        "EXPECTEDKEYUSAGE": true,
        "EXPECTEDUNPREFIX": true,
        "EXPECTEDVALIDJSON": true,
        "EXPECTEDB45DECODE": true,
        "EXPECTEDPICTUREDECODE": true,
        "EXPECTEDEXPIRATIONCHECK": true
    }
}
```

```go
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

```

And the output

```shell
Certificate is verified successfully
Verified health certificate: {
  "iss": "GR",
  "exp": 1683880017,
  "iat": 1622973212,
  "hcert": {
    "eu_dgc_v1": {
      "ver": "1.0.0",
      "nam": {
        "fn": "ΜΕΝΕΞΕΣ",
        "fnt": "MENEXES",
        "gn": "ΜΑΡΙΟΣ",
        "gnt": "MARIOS"
      },
      "dob": "1980-11-11",
      "v": [
        {
          "tg": "840539006",
          "vp": "1119349007",
          "mp": "EU/1/20/1528",
          "ma": "ORG-100030215",
          "dn": 2,
          "sd": 2,
          "dt": "2021-02-19",
          "co": "GR",
          "is": "IDIKA / Ministry of Digital Governance",
          "ci": "URN:UVCI:01:GR:7UXL2ZTSS6KUZAF2XAAA3A4C4I#E"
        }
      ]
    }
  }
}
```

Or you can use your own certificate to verify with a png file containing your QR code with the help of [zbar bar code reader](http://zbar.sourceforge.net/). 

Example usage (essential information omitted)

```shell
% zbarimg --quiet --raw qr.png | go run cmd/qr.go                                                                              
Correct signature against known key identifier vvYa1vaWkGg= and Issuer GR
Verified health certificate: {
  "iss": "GR",
  "exp": 0,
  "iat": 0,
  "hcert": {
    "eu_dgc_v1": {
      "ver": "1.3.0",
      "nam": {
        "fn": "",
        "fnt": "",
        "gn": "",
        "gnt": ""
      },
      "dob": "",
      "v": [
        {
          "tg": "",
          "vp": "",
          "mp": "",
          "ma": "",
          "dn": 0,
          "sd": 0,
          "dt": "",
          "co": "GR",
          "is": "IDIKA / Ministry of Digital Governance",
          "ci": ""
        }
      ]
    }
  }
}
```

Or you can simply start the web server and make queries with curl or any other client.

```shell
% go run cmd/api.go                                                                                    
API is starting to listen the connections on :3000
```

```shell
% curl -d '{"qr": "HC1:6BF+70790T9WJWG.FKY*4GO0.O1CV2 O5 N2FBBRW1*70HS8WY04AC*WIFN0AHCD8KD97TK0F90KECTHGWJC0FDC:5AIA%G7X+AQB9746HS80:54IBQF60R6$A80X6S1BTYACG6M+9XG8KIAWNA91AY%67092L4WJCT3EHS8XJC$+DXJCCWENF6OF63W5NW6WF6%JC QE/IAYJC5LEW34U3ET7DXC9 QE-ED8%E.JCBECB1A-:8$96646AL60A60S6Q$D.UDRYA 96NF6L/5QW6307KQEPD09WEQDD+Q6TW6FA7C466KCN9E%961A6DL6FA7D46JPCT3E5JDLA7$Q6E464W5TG6..DX%DZJC6/DTZ9 QE5$CB$DA/D JC1/D3Z8WED1ECW.CCWE.Y92OAGY8MY9L+9MPCG/D5 C5IA5N9$PC5$CUZCY$5Y$527B+A4KZNQG5TKOWWD9FL%I8U$F7O2IBM85CWOC%LEZU4R/BXHDAHN 11$CA5MRI:AONFN7091K9FKIGIY%VWSSSU9%01FO2*FTPQ3C3F"}' -H "Content-Type: application/json" -X POST http://localhost:3000/api/query
{"status":{"verified":false,"message":"certificate for country DE and key identifier DEsVUSvpFAE= could not be found\n"},"dgc":{"iss":"DE","exp":1643356073,"iat":1622316073,"hcert":{"eu_dgc_v1":{"ver":"1.0.0","nam":{"fn":"Mustermann","fnt":"MUSTERMANN","gn":"Erika","gnt":"ERIKA"},"dob":"1964-08-12","v":[{"tg":"840539006","vp":"1119349007","mp":"EU/1/20/1507","ma":"ORG-100031184","dn":2,"sd":2,"dt":"2021-05-29","co":"DE","is":"Robert Koch-Institut","ci":"URN:UVCI:01DE/IZ12345A/5CWLU12RNOB9RXSEOP6FG8#W"}]}}}}
```