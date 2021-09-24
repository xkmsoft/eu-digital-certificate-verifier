package main

import (
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/xkmsoft/eu-digital-certificate-verifier/pkg/api"
	"log"
	"net/http"
)

func main() {
	port := flag.String("port", "3000", "port")
	flag.Parse()
	router := mux.NewRouter()
	router.HandleFunc("/api/query", api.HandleQuery).Methods("POST")
	address := fmt.Sprintf(":%s", *port)
	fmt.Printf("API is starting to listen the connections on %s\n", address)
	log.Fatal(http.ListenAndServe(address, router))
}
