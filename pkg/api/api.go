package api

import (
	"encoding/json"
	"github.com/xkmsoft/eu-digital-certificate-verifier/pkg/hc1_verifier"
	"net/http"
	"strings"
)

// QueryParams is a simple struct of request data which has only qr code
type QueryParams struct {
	Qr string `json:"qr"`
}

// ErrorResponse is the error struct response which has only field error message
type ErrorResponse struct {
	Error string `json:"error"`
}

// VerificationStatus is a struct to indicate whether the structure is verified or not with the message
// either the fail reason or success message
type VerificationStatus struct {
	Verified bool   `json:"verified"`
	Message  string `json:"message"`
}

// Response struct is the response of HandleQuery function having the VerificationStatus as Status field
// and the DGC as DGC field
type Response struct {
	Status VerificationStatus     `json:"status"`
	DGC    hc1_verifier.CWTClaims `json:"dgc"`
}

// HandleQuery simply handles the http requests to verify the coming QR codes and send appropriate response either
// ErrorResponse or Response having the VerificationStatus and DGC itself
func HandleQuery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var params QueryParams
	var errorResponse ErrorResponse
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		errorResponse.Error = err.Error()
		_ = json.NewEncoder(w).Encode(errorResponse)
		return
	}

	var response Response
	dgc, verified, err := hc1_verifier.VerifyAPI(strings.TrimSpace(params.Qr))
	if dgc == nil {
		// DGC could not be read until the verification process
		errorResponse.Error = err.Error()
		_ = json.NewEncoder(w).Encode(errorResponse)
		return
	}
	if err != nil {
		// DGC could be read but not verified
		response.Status = VerificationStatus{
			Verified: verified,
			Message:  err.Error(),
		}
		response.DGC = dgc.Claims
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	response.Status = VerificationStatus{
		Verified: verified,
		Message:  "Certificate verified successfully",
	}
	response.DGC = dgc.Claims
	if err := json.NewEncoder(w).Encode(response); err != nil {
		errorResponse.Error = err.Error()
		_ = json.NewEncoder(w).Encode(errorResponse)
	}
}
