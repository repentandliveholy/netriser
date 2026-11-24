//go:build !windows

package install

import (
	"bytes"
	"os"
	"testing"
)

func TestEmbeddedInstallScriptMatchesRepository(t *testing.T) {
	repo, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(repo, installScript) {
		t.Fatal("internal/install/install.sh differs from scripts/install.sh: cp scripts/install.sh internal/install/install.sh")
	}
}
