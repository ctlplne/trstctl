// SPDX-License-Identifier: MPL-2.0

package tsa

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"strings"
)

const maxTimeStampReqBytes = 64 * 1024

var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

type asn1AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type asn1MessageImprint struct {
	HashAlgorithm asn1AlgorithmIdentifier
	HashedMessage []byte
}

type asn1TimeStampReq struct {
	Version        int
	MessageImprint asn1MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     asn1.RawValue         `asn1:"optional,tag:0"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type pkiStatusInfo struct {
	Status int
}

type parsedTimeStampReq struct {
	HashedMessage []byte
	Nonce         *big.Int
}

const (
	pkiStatusGranted   = 0
	pkiStatusRejection = 2
)

// Handler returns an RFC 3161 HTTP timestamping endpoint. It accepts a DER
// TimeStampReq over POST and returns a DER TimeStampResp whose token is produced by
// the Authority through the signer-backed crypto boundary.
func (a *Authority) Handler() http.Handler {
	return Handler(a)
}

// Handler adapts an Authority to an RFC 3161 HTTP timestamping endpoint.
func Handler(a *Authority) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isTimeStampQuery(r.Header.Get("Content-Type")) {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTimeStampReqBytes))
		if err != nil {
			writeFailure(w, http.StatusRequestEntityTooLarge)
			return
		}
		parsed, err := parseTimeStampReq(body)
		if err != nil {
			writeFailure(w, http.StatusBadRequest)
			return
		}
		tok, err := a.timestamp(r.Context(), parsed.HashedMessage, parsed.Nonce)
		if err != nil {
			writeFailure(w, http.StatusInternalServerError)
			return
		}
		resp, err := marshalTimeStampResp(tok.DER)
		if err != nil {
			writeFailure(w, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", ContentTypeReply)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
	})
}

func isTimeStampQuery(v string) bool {
	if strings.TrimSpace(v) == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(v)
	if err != nil {
		return false
	}
	return strings.EqualFold(mt, ContentTypeQuery)
}

func parseTimeStampReq(der []byte) (parsedTimeStampReq, error) {
	var req asn1TimeStampReq
	rest, err := asn1.Unmarshal(der, &req)
	if err != nil {
		return parsedTimeStampReq{}, fmt.Errorf("tsa: parse TimeStampReq: %w", err)
	}
	if len(rest) != 0 {
		return parsedTimeStampReq{}, errors.New("tsa: trailing data after TimeStampReq")
	}
	if req.Version != 1 {
		return parsedTimeStampReq{}, fmt.Errorf("tsa: unsupported TimeStampReq version %d", req.Version)
	}
	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return parsedTimeStampReq{}, fmt.Errorf("tsa: unsupported message-imprint hash %v", req.MessageImprint.HashAlgorithm.Algorithm)
	}
	if len(req.MessageImprint.HashedMessage) != 32 {
		return parsedTimeStampReq{}, fmt.Errorf("tsa: SHA-256 message imprint is %d bytes, want 32", len(req.MessageImprint.HashedMessage))
	}
	var nonce *big.Int
	if req.Nonce != nil {
		if req.Nonce.Sign() < 0 {
			return parsedTimeStampReq{}, errors.New("tsa: nonce must be non-negative")
		}
		nonce = new(big.Int).Set(req.Nonce)
	}
	return parsedTimeStampReq{HashedMessage: append([]byte(nil), req.MessageImprint.HashedMessage...), Nonce: nonce}, nil
}

func marshalTimeStampResp(tokenDER []byte) ([]byte, error) {
	if len(tokenDER) == 0 {
		return nil, errors.New("tsa: empty TimeStampToken")
	}
	return asn1.Marshal(timeStampResp{
		Status:         pkiStatusInfo{Status: pkiStatusGranted},
		TimeStampToken: asn1.RawValue{FullBytes: append([]byte(nil), tokenDER...)},
	})
}

func marshalFailureTimeStampResp() []byte {
	der, _ := asn1.Marshal(timeStampResp{Status: pkiStatusInfo{Status: pkiStatusRejection}})
	return der
}

func writeFailure(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", ContentTypeReply)
	w.WriteHeader(status)
	_, _ = w.Write(marshalFailureTimeStampResp())
}
