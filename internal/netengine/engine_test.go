package netengine

import (
	"testing"
	"time"
)

func TestInterfaceMatching(t *testing.T) {
	meshCases := []string{
		"wt0", "wt1", "zt0", "ztuga1234", "tailscale0", "nebula0", "wg0", "wg-mesh", "tun0", "tap0", "utun0", "feth4426",
	}
	for _, iface := range meshCases {
		if !IsMeshInterface(iface) {
			t.Errorf("expected %s to be mesh interface", iface)
		}
		if !IsIgnoredInterface(iface) {
			t.Errorf("expected %s to be ignored interface", iface)
		}
	}

	phyCases := []string{
		"eth0", "enp3s0", "ens33", "en0", "en1", "Ethernet", "Wi-Fi", "wlan0",
	}
	for _, iface := range phyCases {
		if IsMeshInterface(iface) {
			t.Errorf("did not expect %s to be mesh interface", iface)
		}
		if IsIgnoredInterface(iface) {
			t.Errorf("did not expect %s to be ignored interface", iface)
		}
	}

	virtualCases := []string{
		"lo", "docker0", "br-123456", "vethabcdef", "virbr0", "cni0",
	}
	for _, iface := range virtualCases {
		if !IsIgnoredInterface(iface) {
			t.Errorf("expected %s to be ignored interface", iface)
		}
	}
}

func TestBaselineSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	original := Baseline{
		Interface:  "eth0",
		Gateway:    "192.168.1.1",
		IP:         "192.168.1.100",
		DetectedAt: time.Now().Truncate(time.Second),
	}

	if err := SaveBaseline(tmpDir, original); err != nil {
		t.Fatalf("failed to save baseline: %v", err)
	}

	loaded, err := LoadSavedBaseline(tmpDir)
	if err != nil {
		t.Fatalf("failed to load baseline: %v", err)
	}

	if loaded.Interface != original.Interface || loaded.Gateway != original.Gateway || loaded.IP != original.IP {
		t.Fatalf("loaded baseline mismatch: got %+v, want %+v", loaded, original)
	}
}
