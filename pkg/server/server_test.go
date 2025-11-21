package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
				// normal test: root is a directory
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
