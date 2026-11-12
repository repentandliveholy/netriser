// Command netriser-sign creates the release-signing key and signs release
// files. It is a maintainer tool and is not part of the installed application.
//
//	go run ./cmd/netriser-sign keygen [-out PATH]
//	go run ./cmd/netriser-sign sign [-key PATH] FILE...      (writes FILE.sig)
//	go run ./cmd/netriser-sign verify [-pub BASE64] FILE...  (default: built-in keys)
//	go run ./cmd/netriser-sign pubkey [-key PATH]
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/repentandliveholy/netriser/internal/updater"
)

func defaultKeyPath() string {
	if p := os.Getenv("NETRISER_SIGNING_KEY"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "release-signing.key"
	}
	return filepath.Join(home, ".config", "netriser", "release-signing.key")
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "pubkey":
		err = pubkey(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "netriser-sign:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: netriser-sign keygen|sign|verify|pubkey [flags] [files]")
	os.Exit(2)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", defaultKeyPath(), "private key file to create")
	_ = fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("refusing to overwrite or create %s: %w", *out, err)
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("Private key: %s (keep it secret and backed up)\nPublic key:  %s\n", *out, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("signing key %s must not be readable by group or others (chmod 600)", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key is not a base64 Ed25519 private key")
	}
	return ed25519.PrivateKey(raw), nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", defaultKeyPath(), "private key file")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("no files to sign")
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	for _, name := range fs.Args() {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(name+".sig", []byte(updater.Sign(data, key)+"\n"), 0644); err != nil {
			return err
		}
		fmt.Printf("Signed %s -> %s.sig\n", name, name)
	}
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pub := fs.String("pub", "", "base64 public key (default: keys built into NetRiser)")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("no files to verify")
	}
	var keys []ed25519.PublicKey
	var err error
	if *pub != "" {
		k, perr := updater.ParsePublicKey(*pub)
		if perr != nil {
			return perr
		}
		keys = []ed25519.PublicKey{k}
	} else if keys, err = updater.TrustedKeys(nil); err != nil {
		return err
	}
	for _, name := range fs.Args() {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(name + ".sig")
		if err != nil {
			return err
		}
		if err := updater.VerifySignature(data, sig, keys); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Printf("OK %s\n", name)
	}
	return nil
}

func pubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	keyPath := fs.String("key", defaultKeyPath(), "private key file")
	_ = fs.Parse(args)
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
	return nil
}
