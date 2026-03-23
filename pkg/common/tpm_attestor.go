/*
 ** Copyright 2019 Bloomberg Finance L.P.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package common

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-attestation/attest"
)

const (
	PluginName = "tpm"
)

type AttestationData struct {
	EK []byte
	AK *attest.AttestationParameters
	AWS *AWSInstanceData
	PVE *PVEInstanceData
}

type AWSInstanceData struct {
	InstanceID string `json:"instance_id"`
}

type PVEInstanceData struct {
	UUID string `json:"uuid"`
	VMID int32  `json:"vmid"`
}

type Challenge struct {
	EC *attest.EncryptedCredential
}

type KeyData struct {
	Keys []string `json:"keys"`
}

type ChallengeResponse struct {
	Secret []byte
}

func AgentID(trustDomain string, pubHash string) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   strings.Join([]string{"spire", "agent", "tpm", pubHash}, "/"),
	}
	return u.String()
}

func GetPubHash(ek *attest.EK) (string, error) {
	data, err := pubBytes(ek)
	if err != nil {
		return "", err
	}
	pubHash := sha256.Sum256(data)
	hashEncoded := fmt.Sprintf("%x", pubHash)
	return hashEncoded, nil
}

func EncodeEK(ek *attest.EK) ([]byte, error) {
	var buf bytes.Buffer
	if ek.Certificate != nil {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ek.Certificate.Raw}); err != nil {
			return nil, err
		}
	}

	data, err := pubBytes(ek)
	if err != nil {
		return nil, err
	}

	if err := pem.Encode(&buf, &pem.Block{Type: "PUBLIC KEY", Bytes: data}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func pubBytes(ek *attest.EK) ([]byte, error) {
	data, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		return nil, fmt.Errorf("error marshaling EKPub key: %v", err)
	}
	return data, nil
}

func DecodeEK(pemBytes []byte) (*attest.EK, error) {
	blockOne, rest := pem.Decode(pemBytes)

	if blockOne == nil {
		return nil, errors.New("invalid pemBytes")
	}

	ek := &attest.EK{}
	if err := decodeEKBlock(blockOne, ek); err != nil {
		return nil, err
	}

	if rest != nil {
		if blockTwo, _ := pem.Decode(rest); blockTwo != nil {
			if err := decodeEKBlock(blockTwo, ek); err != nil {
				return nil, err
			}
		}
	}

	return ek, nil
}

func decodeEKBlock(b *pem.Block, ek *attest.EK) error {
	switch b.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing EKCert: %v", err)
		}
		ek.Certificate = cert
		return nil

	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing EKPub key: %v", err)
		}
		ek.Public = pub
		return nil
	}

	return fmt.Errorf("invalid pem type: %s", b.Type)
}
