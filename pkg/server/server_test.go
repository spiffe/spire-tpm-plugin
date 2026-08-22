package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_checkHashAllowed(t *testing.T) {
	tests := []struct {
		name           string
		setupFile      bool
		setupStatError bool
		hashEncoded    string
		rootIsFile     bool
		want           bool
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
			name:        "empty hash does not match directory",
			hashEncoded: "",
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
		{
			// Any lookup error other than a missing allowlist entry must also
			// fail closed. A self-referential symlink produces ELOOP reliably,
			// including when the test runs as root.
			name:           "hash lookup returns an unexpected stat error",
			setupStatError: true,
			hashEncoded:    "stat-error-hash",
			want:           false,
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

			if tt.setupStatError {
				path := filepath.Join(root, tt.hashEncoded)
				if err := os.Symlink(tt.hashEncoded, path); err != nil {
					t.Fatalf("failed to create self-referential symlink: %v", err)
				}
			}

			got := checkHashAllowed(root, tt.hashEncoded)
			assert.Equal(t, got, tt.want)
		})
	}
}
