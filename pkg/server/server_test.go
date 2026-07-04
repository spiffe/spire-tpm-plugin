package server

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The event log fixtures in testdata/ are copied from
// github.com/google/go-attestation (attest/testdata/)
//
// windows_gcp_shielded_vm.json is a full attestation dump. Raw event log plus
// the PCR values it replays to from a machine booted with secure boot on.
// ubuntu_2104_shielded_vm_no_secure_boot_eventlog is a raw event log from a
// machine booted with secure boot off which ships without PCR values, so tests
// reconstruct them by replaying the log.

// eventLogDump mirrors the parts of go-attestations test Dump type needed to
// read the windows_gcp_shielded_vm.json fixture
type eventLogDump struct {
	Log struct {
		PCRs []attest.PCR
		Raw  []byte
	}
}

// replayPCRs computes the PCR values an event log resolves to by extending
// each event digest yielding PCRs that el.Verify() accepts.
func replayPCRs(t *testing.T, el *attest.EventLog) []attest.PCR {
	var pcrs []attest.PCR
	for _, alg := range el.Algs {
		var h crypto.Hash
		switch alg {
		case attest.HashSHA1:
			h = crypto.SHA1
		case attest.HashSHA256:
			h = crypto.SHA256
		default:
			continue
		}

		state := map[int][]byte{}
		for _, event := range el.Events(alg) {
			if len(event.Digest) == 0 {
				continue
			}
			cur, ok := state[event.Index]
			if !ok {
				cur = make([]byte, h.Size())
			}
			hasher := h.New()
			hasher.Write(cur)
			hasher.Write(event.Digest)
			state[event.Index] = hasher.Sum(nil)
		}

		for index, digest := range state {
			pcrs = append(pcrs, attest.PCR{Index: index, Digest: digest, DigestAlg: h})
		}
	}

	require.NotEmpty(t, pcrs)
	return pcrs
}

func Test_parseSecureBootState(t *testing.T) {
	t.Run("secure boot enabled", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("testdata", "windows_gcp_shielded_vm.json"))
		require.NoError(t, err)

		var dump eventLogDump
		require.NoError(t, json.Unmarshal(data, &dump))

		enabled, err := parseSecureBootState(&attest.PlatformParameters{
			EventLog: dump.Log.Raw,
			PCRs:     dump.Log.PCRs,
		})
		require.NoError(t, err)
		assert.True(t, enabled)
	})

	t.Run("secure boot disabled", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join("testdata", "ubuntu_2104_shielded_vm_no_secure_boot_eventlog"))
		require.NoError(t, err)

		el, err := attest.ParseEventLog(raw)
		require.NoError(t, err)

		enabled, err := parseSecureBootState(&attest.PlatformParameters{
			EventLog: raw,
			PCRs:     replayPCRs(t, el),
		})
		require.NoError(t, err)
		assert.False(t, enabled)
	})

	t.Run("error on malformed event log", func(t *testing.T) {
		_, err := parseSecureBootState(&attest.PlatformParameters{
			EventLog: []byte("malformed event log"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error parsing eventlog")
	})

	t.Run("error on PCRs not matching event log", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("testdata", "windows_gcp_shielded_vm.json"))
		require.NoError(t, err)

		var dump eventLogDump
		require.NoError(t, json.Unmarshal(data, &dump))

		// Tampered PCR values must not produce a secure boot state
		for i := range dump.Log.PCRs {
			dump.Log.PCRs[i].Digest = make([]byte, len(dump.Log.PCRs[i].Digest))
		}

		_, err = parseSecureBootState(&attest.PlatformParameters{
			EventLog: dump.Log.Raw,
			PCRs:     dump.Log.PCRs,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error verifying events")
	})
}

func Test_checkHashAllowed(t *testing.T) {
	tests := []struct {
		name        string
		setupFile   bool
		hashEncoded string
		rootIsFile  bool
		want        bool
	}{
		{
			name:        "hash exists",
			setupFile:   true,
			hashEncoded: "example-hash-abc",
			want:        true,
		},
		{
			name:        "hash does not exist",
			setupFile:   false,
			hashEncoded: "not-an-example-hash",
			want:        false,
		},
		{
			// We don't want to be fail-open in the case the user
			// makes the hash_path parameter a file instead of a directory
			// Previously this would allow all hashes to attest
			name:        "directory is erroneously a file",
			setupFile:   false,
			rootIsFile:  true,
			hashEncoded: "example-hash-abc",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var root string
			if tt.rootIsFile {
				f, err := os.CreateTemp("", "hashes")
				if err != nil {
					t.Fatalf("failed to create temp root file: %v", err)
				}
				root = f.Name()
				_ = f.Close()

			} else {
				root = t.TempDir()
				if tt.setupFile {
					path := filepath.Join(root, tt.hashEncoded)
					if err := os.WriteFile(path, []byte{}, 0644); err != nil {
						t.Fatalf("failed to create test file: %v", err)
					}
				}
			}

			if tt.setupFile {
				path := filepath.Join(root, tt.hashEncoded)
				if err := os.WriteFile(path, []byte(""), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
			}

			got := checkHashAllowed(root, tt.hashEncoded)
			assert.Equal(t, got, tt.want)
		})
	}
}
