package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bloomberg/spire-tpm-plugin/pkg/common"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
)

var (
	pveStorageRegex = regexp.MustCompile(`^(ide|scsi|virtio|sata)\d+$`)
	pveNetworkRegex = regexp.MustCompile(`^net\d+$`)
)

type PVEGlobalConfig struct {
	Enabled  bool                 `hcl:"enabled"`
	Clusters map[string]PVEConfig `hcl:"cluster"`
}

type PVEConfig struct {
	Hosts            []string `hcl:"hosts"`              // List of PVE control plane hosts
	Port             int      `hcl:"port"`               // Optional port, defaults to 9443
	ExpectedSpiffeID string   `hcl:"expected_spiffe_id"` // SPIFFE ID to validate on PVE nodes
	HashPath         string   `hcl:"hash_path"`          // Optional path to check hashes
	//FIXME consider an option for limiting join by selectors
}

func (p *Plugin) validatePVEConfig(config *Config, trustdomain string) error {
	if config.PVE.Enabled {
		newClusters := make(map[string]PVEConfig)
		if len(config.PVE.Clusters) == 0 {
			return errors.New("at least one pve cluster must be defined when pve is enabled")
		}
		for name, cluster := range config.PVE.Clusters {
			if cluster.Port == 0 {
				cluster.Port = 9443
			}
			if len(cluster.Hosts) == 0 {
				return fmt.Errorf("pve hosts list is required for cluster %s", name)
			}
			if cluster.ExpectedSpiffeID == "" {
				cluster.ExpectedSpiffeID = "spiffe://" + trustdomain + "/spiffe-pve-ek"
			}
			if cluster.HashPath != "" {
				if _, err := os.Stat(config.HashPath); os.IsNotExist(err) {
					return errors.New(fmt.Sprintf("hash_path '%s' does not exist", cluster.HashPath))
				}
			}
			newClusters[strings.ReplaceAll(name, "-", "")] = cluster
		}
		config.PVE.Clusters = newClusters
	}
	return nil
}

func (p *Plugin) verifyPVETPM(ctx context.Context, pveid *common.PVEInstanceData, ekPub crypto.PublicKey, identity *identityproviderv1.FetchX509IdentityResponse, conf PVEConfig) ([]string, error) {

	i := identity.GetIdentity()
	if i == nil {
		return nil, fmt.Errorf("no identity found in response")
	}
	key, err := x509.ParsePKCS8PrivateKey(i.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: i.CertChain,
		PrivateKey:  key,
	}

	certPool := x509.NewCertPool()
	for _, authority := range identity.Bundle.X509Authorities {
		ca, err := x509.ParseCertificate(authority.Asn1)
		if err != nil {
			return nil, fmt.Errorf("failed to parse trust bundle")
		}
		certPool.AddCert(ca)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{*cert},
				RootCAs:            certPool,
				InsecureSkipVerify: true, // Verification handled in VerifyConnection
				VerifyConnection: func(cs tls.ConnectionState) error {
					opts := x509.VerifyOptions{
						Roots:         certPool,
						Intermediates: x509.NewCertPool(),
					}
					for _, c := range cs.PeerCertificates[1:] {
						opts.Intermediates.AddCert(c)
					}
					_, err := cs.PeerCertificates[0].Verify(opts)
					if err != nil {
						return fmt.Errorf("failed to verify certificate chain: %w", err)
					}
					for _, uri := range cs.PeerCertificates[0].URIs {
						if uri.String() == conf.ExpectedSpiffeID {
							return nil
						}
					}
					return errors.New("remote SPIFFE ID mismatch")
				},
			},
		},
	}

	var targetNode string
	tempHosts := append([]string{}, conf.Hosts...)
	rand.Seed(time.Now().UnixNano())

	for try := 0; try < 3 && len(tempHosts) > 0; try++ {
		idx := rand.Intn(len(tempHosts))
		host := tempHosts[idx]
		tempHosts = append(tempHosts[:idx], tempHosts[idx+1:]...) // Remove chosen host

		lookupURL, _ := url.JoinPath("https://"+host+":"+strconv.Itoa(conf.Port), "vm-to-node", strconv.Itoa(int(pveid.VMID)))
		res, err := client.Get(lookupURL)
		if err != nil {
			continue
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			continue
		}

		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			continue
		}
		targetNode = strings.TrimSpace(string(body))
		break
	}

	if targetNode == "" {
		return nil, fmt.Errorf("could not resolve VM %d to a node after retries", pveid.VMID)
	}

	origionalNode := targetNode
	if !strings.Contains(targetNode, ":") {
		targetNode = fmt.Sprintf("%s:%d", targetNode, conf.Port)
	}

	fullURL, _ := url.JoinPath("https://"+targetNode, "ek-cert", strconv.Itoa(int(pveid.VMID)), pveid.UUID)
	res, err := client.Get(fullURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EK from node")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("target node returned error status: %d", res.StatusCode)
	}

	pveBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body")
	}

	block, _ := pem.Decode(pveBody)
	if block == nil {
		return nil, errors.New("failed to decode PEM block from PVE node")
	}

	pveCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PVE cert: %w", err)
	}

	pveKeyBytes, _ := x509.MarshalPKIXPublicKey(pveCert.PublicKey)
	attestorKeyBytes, _ := x509.MarshalPKIXPublicKey(ekPub)

	if !bytes.Equal(pveKeyBytes, attestorKeyBytes) {
		return nil, errors.New("EK mismatch: PVE certificate key does not match attestor key")
	}

	selectors := []string{
		"pve:cuid:" + pveid.CUID,
		"pve:vm_id:" + strconv.Itoa(int(pveid.VMID)),
		"pve:uuid:" + pveid.UUID,
		"pve:node:" + origionalNode,
	}
	fullURL, _ = url.JoinPath("https://"+targetNode, "vm-metadata", strconv.Itoa(int(pveid.VMID)))
	res, err = client.Get(fullURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EK from node")
	}
	defer res.Body.Close()
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata body")
	}
	var metadata map[string]interface{}
	if err = json.Unmarshal(bodyBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to read metadata")
	}
	if value, ok := metadata["smbios1"]; !ok {
		return nil, fmt.Errorf("failed to read smbios metadata")
	} else {
		uuidOk := false
		vmidOk := false
		val, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("failed to read smbios metadata value")
		}
		items := strings.Split(val, ",")
		for _, item := range items {
			kv := strings.SplitN(item, "=", 2)
			if len(kv) != 2 {
				continue
			}
			if kv[0] == "uuid" && kv[1] == pveid.UUID {
				uuidOk = true
			}
			if kv[0] == "sku" && kv[1] == strconv.Itoa(int(pveid.VMID)) {
				vmidOk = true
			}
		}
		if !vmidOk || !uuidOk {
			return nil, fmt.Errorf("pve smbios data did not match vm")
		}
	}
	if value, ok := metadata["name"]; ok {
		val, ok := value.(string)
		if ok {
			selectors = append(selectors, "pve:name:"+val)
		}
	}
	if value, ok := metadata["tags"]; ok {
		val, ok := value.(string)
		if ok {
			items := strings.Split(val, ";")
			for _, item := range items {
				selectors = append(selectors, "pve:tag:"+item)
			}
		}
	}
	for key, value := range metadata {
		val, ok := value.(string)
		if ok {
			if pveStorageRegex.MatchString(key) {
				parts := strings.SplitN(val, ",", 2)
				idParts := strings.SplitN(parts[0], ":", 2)
				if len(idParts) == 2 {
					selectors = append(selectors, fmt.Sprintf("pve:storage:%s:%s", idParts[0], idParts[1]))
				}
			} else if pveNetworkRegex.MatchString(key) {
				netParams := make(map[string]string)
				pairs := strings.Split(val, ",")
				for _, pair := range pairs {
					kv := strings.SplitN(pair, "=", 2)
					if len(kv) == 2 {
						netParams[kv[0]] = kv[1]
					}
				}
				bridge, hasBridge := netParams["bridge"]
				tag, hasTag := netParams["tag"]
				if hasBridge {
					if hasTag {
						selectors = append(selectors, fmt.Sprintf("pve:network:%s:%s", bridge, tag))
					} else {
						selectors = append(selectors, fmt.Sprintf("pve:network:%s", bridge))
					}
				}
			}
		}
	}
	return selectors, nil
}
