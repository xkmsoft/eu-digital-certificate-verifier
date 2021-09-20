package main

import (
	"fmt"
	"github.com/xkmsoft/eu-digital-certificate-verifier/pkg/hc1_verifier"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func main() {
	in, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("could not read qr code from std input: %s", err.Error())
	}
	qr := strings.TrimSpace(string(in))
	dgc, err := hc1_verifier.Verify(qr)
	if err != nil {
		log.Fatal(err)
	}
	claims, err := dgc.ToJSONClaims()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Verified health certificate: %s\n", claims)
}
