package agent

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/cofide/spire-tpm-plugin/pkg/common_test"
	"github.com/cofide/spire-tpm-plugin/pkg/server"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/client"
	sim "github.com/google/go-tpm-tools/simulator"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	agentnodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	servernodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/require"
)

var (
	trustDomain            = "domain.test"
	hashExpected           = "1b5bbe2e96054f7bc34ebe7ba9a4a9eac5611c6879285ceff6094fa556af485c"
	selectorValuesExpected = []string{"pub_hash:" + hashExpected}
	idExpected             = "spiffe://" + trustDomain + "/spire/agent/tpm/" + hashExpected
	invalidHash            = "0000000000000000000000000000000000000000000000000000000000000000"
	invalidCAPEM           = []byte(`-----BEGIN CERTIFICATE-----
MIIDjDCCAnSgAwIBAgIUWe6uPQG5Z+xnccBoXH9ui6dORgMwDQYJKoZIhvcNAQEL
BQAwYTEZMBcGA1UECgwQVFBNIE1hbnVmYWN0dXJlcjEhMB8GA1UECwwYVFBNIE1h
bnVmYWN0dXJlciBSb290IENBMSEwHwYDVQQDDBhUUE0gTWFudWZhY3R1cmVyIFJv
b3QgQ0EwHhcNMjAwNTA3MjA0NDQ3WhcNMzAwNTA3MjA0NDQ3WjBhMRkwFwYDVQQK
DBBUUE0gTWFudWZhY3R1cmVyMSEwHwYDVQQLDBhUUE0gTWFudWZhY3R1cmVyIFJv
b3QgQ0ExITAfBgNVBAMMGFRQTSBNYW51ZmFjdHVyZXIgUm9vdCBDQTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAK7xKAhZMXr4gd+KqdAks+fqJOUIS5td
D1wuc7lTFv9oXUg+3adkM0c2X4u8zmqu01DE1JuSrbDPsnuDNtm0gX5YPwod5jgT
+nnWFs5uipRk0+Wbakw3+rnFP5VuI7rO+ZDQEgN/F+xxvawOJOwPDhR0CO+ENqLM
WVSclBBqOESezecZDqq+LaDMxMe2+3dhRuomhcL1x9jygWoZx4xpRhLdMS2O+O9k
0AFR06CVoCxPPt7ErjXKJycXNucWpPxVK1Kxrq+PFuBZm7PtOBg/+uaFg5FzbBox
5ftpGp/oFZhEs5Z2JZ7DGYH865vKbud0/lP5QSCM7Vk8dbvZu1LoWs8CAwEAAaM8
MDowHQYDVR0OBBYEFGNVc7Gbhb2fwimbEj6cUfcKCrclMAwGA1UdEwQFMAMBAf8w
CwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQBmXwOZ+HUUaZ7xib3FsNg/
1M8W+R1sIl3X/cBorwh2XGsYSzHlrlFO62LyGzM6VCawBVC2HsEmYi/o7Bi8RTph
lRAN6NWwQ2FaYw6sKzlXFeEGPkamIPbOFwP02OP2mYNlMDoYvgFpZjuVbZTtQH8F
litUyWe49TAfNcIRz9DVW72U0KL7kaqP5T4elje65L6oRE3PUlbrNLynxbOvBlr0
yiDzSj4A2Iqxbhkp2MLGuPR6e5MkLLfeHIdos4uVGgzmcyVU6+wss0QPqNMrfANn
80Ur8/Y9v//wSdaU+AsDfrBNiXgmp7sJ4jsvt+P8xTLTTCNmN2Pewh9N8Q3RwMZV
-----END CERTIFICATE-----
`)
)

func TestAttestor(t *testing.T) {
	s, err := sim.GetWithFixedSeedInsecure(0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CheckedClose(t, s)

	invalidCA := pemToCertificate(t, invalidCAPEM)

	tpm, err := attest.OpenTPM(&attest.OpenConfig{
		TPMVersion:     attest.TPMVersion20,
		CommandChannel: &common_test.TPMCmdChannel{ReadWriteCloser: s},
	})
	if err != nil {
		t.Fatal(err)
	}

	tpmCACert, log, err := common_test.LoadEKCert(s)
	if err != nil {
		if log != nil {
			t.Error(log)
		}
		t.Fatal(err)
	}

	testCases := []struct {
		name           string
		emptyCA        bool
		err            string
		hcl            string
		pemEncodeCAs   bool
		validateCAs    []*x509.Certificate
		validateHashes []string
	}{
		{
			name:         "valid CA certificate PEM format",
			validateCAs:  []*x509.Certificate{tpmCACert},
			pemEncodeCAs: true,
		},
		{
			name:        "valid CA certificate DER format",
			validateCAs: []*x509.Certificate{tpmCACert},
		},
		{
			name:        "valid multiple CAs",
			validateCAs: []*x509.Certificate{tpmCACert, invalidCA},
		},
		{
			name:           "valid hash",
			validateHashes: []string{hashExpected},
		},
		{
			name:           "valid hash",
			validateHashes: []string{hashExpected},
		},
		{
			name:           "valid CA, invalid hash",
			validateCAs:    []*x509.Certificate{tpmCACert},
			validateHashes: []string{invalidHash},
		},
		{
			name:           "valid hash, invalid CA",
			validateCAs:    []*x509.Certificate{invalidCA},
			validateHashes: []string{hashExpected},
		},
		{
			name:    "error empty CA",
			emptyCA: true,
			err:     "could not verify cert",
		},
		{
			name:        "error invalid CA",
			validateCAs: []*x509.Certificate{invalidCA},
			err:         "could not verify cert",
		},
		{
			name:           "error invalid hash",
			validateHashes: []string{invalidHash},
			err:            "could not validate EK",
		},
		{
			name:           "error invalid hash, invalid CA",
			validateCAs:    []*x509.Certificate{invalidCA},
			validateHashes: []string{invalidHash},
			err:            "could not verify cert",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require := require.New(t)

			// prepare the temp directory
			hcl := prepareTestDir(t, testCase.validateCAs, testCase.pemEncodeCAs,
				testCase.emptyCA, testCase.validateHashes)
			if testCase.hcl != "" {
				hcl = testCase.hcl
			}

			// load up the fake agent-side node attestor
			agentPlugin := loadAgentPlugin(t, tpm)
			serverPlugin := loadServerPlugin(t, hcl)

			attribs, err := doAttestationFlow(t, agentPlugin, serverPlugin)
			if testCase.err != "" {
				require.Error(err)
				require.Contains(err.Error(), testCase.err)
				return
			}

			require.NoError(err)
			require.NotNil(attribs)
			require.Equal(idExpected, attribs.SpiffeId)
			require.Equal(selectorValuesExpected, attribs.SelectorValues)
		})
	}
}

func doAttestationFlow(t *testing.T, agentPlugin agentnodeattestorv1.NodeAttestorClient, serverPlugin servernodeattestorv1.NodeAttestorClient) (*servernodeattestorv1.AgentAttributes, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentStream, err := agentPlugin.AidAttestation(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed opening agent AidAttestation stream: %w", err)
	}

	serverStream, err := serverPlugin.Attest(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed opening server Attest stream: %w", err)
	}

	agentResp, err := agentStream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive payload from agent plugin: %w", err)
	}

	require.NotEmpty(t, agentResp.GetPayload(), "agent plugin responded with an empty payload")

	if err := serverStream.Send(&servernodeattestorv1.AttestRequest{
		Request: &servernodeattestorv1.AttestRequest_Payload{
			Payload: agentResp.GetPayload(),
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to send payload to server plugin: %w", err)
	}

	for {
		serverResp, err := serverStream.Recv()
		if err != nil {
			return nil, fmt.Errorf("failed to receive response from server plugin: %w", err)
		}

		if attribs := serverResp.GetAgentAttributes(); attribs != nil {
			return attribs, nil
		}

		require.NotEmpty(t, serverResp.GetChallenge(), "server plugin responded with an empty challenge")

		if err := agentStream.Send(&agentnodeattestorv1.Challenge{
			Challenge: serverResp.GetChallenge(),
		}); err != nil {
			return nil, fmt.Errorf("failed to send challenge to agent plugin: %w", err)
		}

		agentResp, err := agentStream.Recv()
		if err != nil {
			return nil, fmt.Errorf("failed to receive challenge response from agent plugin: %w", err)
		}

		require.Nil(t, agentResp.GetPayload(), "agent plugin responded with a payload instead of a challenge")
		require.NotEmpty(t, agentResp.GetChallengeResponse(), "agent plugin responded with an empty challenge response")

		if err := serverStream.Send(&servernodeattestorv1.AttestRequest{
			Request: &servernodeattestorv1.AttestRequest_ChallengeResponse{
				ChallengeResponse: agentResp.GetChallengeResponse(),
			},
		}); err != nil {
			return nil, fmt.Errorf("failed to send payload to server plugin: %w", err)
		}
	}
}

func prepareTestDir(t *testing.T, caCerts []*x509.Certificate,
	pemEncodeCA bool, emptyCA bool, hashes []string,
) string {
	dir := t.TempDir()

	hcl := ""
	if emptyCA || caCerts != nil {
		caCertPath := filepath.Join(dir, "certs")
		hcl += fmt.Sprintf("ca_path = \"%s\"\n", caCertPath)
		require.NoError(t, os.Mkdir(caCertPath, 0o755))
		if caCerts != nil {
			for i := range caCerts {
				caCert := caCerts[i]
				var b []byte
				if pemEncodeCA {
					b = certificateToPEM(caCert)
				} else {
					b = caCert.Raw
				}
				writeFile(t, filepath.Join(caCertPath, fmt.Sprintf("ca.%d.crt", i)), b, 0o644)
			}
		}
	}

	if hashes != nil {
		hashPath := filepath.Join(dir, "hashes")
		hcl += fmt.Sprintf("hash_path = \"%s\"\n", hashPath)
		require.NoError(t, os.Mkdir(hashPath, 0o755))
		for i := range hashes {
			writeFile(t, filepath.Join(hashPath, hashes[i]), []byte{}, 0o644)
		}
	}

	return hcl
}

func loadAgentPlugin(t *testing.T, tpm *attest.TPM) agentnodeattestorv1.NodeAttestorClient {
	p := New()
	p.tpm = tpm

	nodeAttestorClient := new(agentnodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer:   agentnodeattestorv1.NodeAttestorPluginServer(p),
		PluginClient:   nodeAttestorClient,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(p)},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})

	_, err := configClient.Validate(context.Background(), &configv1.ValidateRequest{
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: trustDomain,
		},
	})
	require.NoError(t, err)

	_, err = configClient.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: trustDomain,
		},
	})
	require.NoError(t, err)
	return nodeAttestorClient
}

func loadServerPlugin(t *testing.T, hclConfig string) servernodeattestorv1.NodeAttestorClient {
	// load up the fake server-side node attestor
	p := server.New()

	nodeAttestorClient := new(servernodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer:   servernodeattestorv1.NodeAttestorPluginServer(p),
		PluginClient:   nodeAttestorClient,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(p)},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})

	_, err := configClient.Validate(context.Background(), &configv1.ValidateRequest{
		HclConfiguration: hclConfig,
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: trustDomain,
		},
	})
	require.NoError(t, err)

	_, err = configClient.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: hclConfig,
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: trustDomain,
		},
	})
	require.NoError(t, err)
	return nodeAttestorClient
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	require.NoError(t, ioutil.WriteFile(path, data, mode))
}

func pemToCertificate(t *testing.T, pemBytes []byte) *x509.Certificate {
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	require.Equal(t, block.Type, "CERTIFICATE")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func certificateToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}
