package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/cofide/spire-tpm-plugin/pkg/common"
	"github.com/google/go-attestation/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeStore_Attest_Success(t *testing.T) {
	tmpDir := t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ekWrapper := &attest.EK{Public: &key.PublicKey}
	hashEncoded, err := common.GetPubHash(ekWrapper)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tmpDir, hashEncoded), []byte{}, 0644)
	require.NoError(t, err)

	config := &Config{
		trustDomain: "example.org",
		HashPath:    tmpDir,
	}
	p := NewFromConfig(config)

	err = p.ns.Attest(context.Background(), ekWrapper)
	assert.NoError(t, err, "NodeStore should validate the EK against the file on disk")
}

func TestNodeStore_Attest_Failure(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ekWrapper := &attest.EK{Public: &key.PublicKey}

	p := NewFromConfig(&Config{
		trustDomain: "example.org",
		HashPath:    t.TempDir(),
	})

	err := p.ns.Attest(context.Background(), ekWrapper)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not validate EK")
}
