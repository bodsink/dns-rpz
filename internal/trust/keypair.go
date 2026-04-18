// Package trust implements the trust network for DNS-RPZ nodes.
// It handles Ed25519 keypairs, hash-chained ledger, gossip protocol,
// and threshold signature consensus.
package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Keypair holds the Ed25519 identity of this node.
type Keypair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// PublicKeyBase64 returns the public key encoded as standard base64.
func (kp *Keypair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.Public)
}

// Fingerprint returns the SHA-256 fingerprint of the public key
// in the format "SHA256:<base64>" (like SSH key fingerprints).
func (kp *Keypair) Fingerprint() string {
	h := sha256.Sum256(kp.Public)
	return "SHA256:" + base64.StdEncoding.EncodeToString(h[:])
}

// FingerprintFromPubKeyBase64 computes a SHA-256 fingerprint from a
// base64-encoded Ed25519 public key string. Returns empty string on error.
// Used to display TOFU fingerprints when the local Keypair is not available.
func FingerprintFromPubKeyBase64(pubKeyBase64 string) string {
	if pubKeyBase64 == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(raw)
	return "SHA256:" + base64.StdEncoding.EncodeToString(h[:])
}

// Sign signs the given message and returns the signature.
func (kp *Keypair) Sign(message []byte) []byte {
	return ed25519.Sign(kp.Private, message)
}

// Verify checks a signature produced by this keypair's public key.
func (kp *Keypair) Verify(message, sig []byte) bool {
	return ed25519.Verify(kp.Public, message, sig)
}

// SignBatch produces an Ed25519 signature over an AXFR batch.
// The message is the SHA-256 hash of: zone_id (8 bytes big-endian) ||
// serial (8 bytes big-endian) || each name (sorted, newline-separated).
// Returns the base64-encoded signature, or an error if signing fails.
func (kp *Keypair) SignBatch(zoneID, serial int64, names []string) (string, error) {
	msg := batchMessage(zoneID, serial, names)
	sig := ed25519.Sign(kp.Private, msg)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// batchMessage builds the canonical byte representation of an AXFR batch
// for signing/verification: SHA-256(zone_id_BE8 || serial_BE8 || sorted_names_NL).
func batchMessage(zoneID, serial int64, names []string) []byte {
	sorted := make([]string, len(names))
	copy(sorted, names)
	sort.Strings(sorted)

	h := sha256.New()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(zoneID))
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(serial))
	h.Write(buf[:])
	h.Write([]byte(strings.Join(sorted, "\n")))
	return h.Sum(nil)
}

// VerifyBatch verifies a base64-encoded Ed25519 signature over an AXFR batch
// using the given public key (base64-encoded).
func VerifyBatch(pubKeyBase64, batchSigBase64 string, zoneID, serial int64, names []string) bool {
	pubRaw, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return false
	}
	sigRaw, err := base64.StdEncoding.DecodeString(batchSigBase64)
	if err != nil {
		return false
	}
	msg := batchMessage(zoneID, serial, names)
	return ed25519.Verify(ed25519.PublicKey(pubRaw), msg, sigRaw)
}

// LoadOrCreate loads the Ed25519 keypair from keyPath.
// If the file does not exist, it generates a new keypair and saves it.
// If the file exists but is corrupt, it returns an error without overwriting.
func LoadOrCreate(keyPath string) (*Keypair, error) {
	kp, err := loadKeypair(keyPath)
	if err == nil {
		return kp, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		// File exists but cannot be read/parsed — do NOT overwrite.
		return nil, fmt.Errorf("node key at %s is corrupt or unreadable: %w — "+
			"restore from backup or delete to generate a new identity", keyPath, err)
	}

	// File does not exist — generate a new keypair.
	kp, err = generateKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate node keypair: %w", err)
	}
	if err := saveKeypair(keyPath, kp); err != nil {
		return nil, fmt.Errorf("save node keypair to %s: %w", keyPath, err)
	}

	slog.Info("Node identity created",
		slog.String("public_key", kp.PublicKeyBase64()),
		slog.String("key_path", keyPath),
	)
	slog.Warn("IMPORTANT: Backup " + keyPath)
	slog.Warn("Losing this file means losing your node identity permanently")

	return kp, nil
}

// generateKeypair creates a fresh Ed25519 keypair using crypto/rand.
func generateKeypair() (*Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Keypair{Private: priv, Public: pub}, nil
}

// saveKeypair writes the private key to keyPath using PEM format, mode 0600.
// Parent directories are created automatically.
func saveKeypair(keyPath string, kp *Keypair) error {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: kp.Private.Seed(), // 32-byte seed, portable
	}
	return pem.Encode(f, block)
}

// loadKeypair reads a PEM-encoded Ed25519 private key from keyPath.
func loadKeypair(keyPath string) (*Keypair, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block (expected ED25519 PRIVATE KEY)")
	}
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid key seed length: got %d, want %d",
			len(block.Bytes), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(block.Bytes)
	pub := priv.Public().(ed25519.PublicKey)
	return &Keypair{Private: priv, Public: pub}, nil
}

// VerifyRemotePublicKey checks whether the given base64-encoded public key
// matches the expected fingerprint. Used for TOFU (Trust On First Use) verification.
func VerifyRemotePublicKey(pubKeyBase64, expectedFingerprint string) (bool, error) {
	raw, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return false, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key length: %d", len(raw))
	}
	h := sha256.Sum256(raw)
	fp := "SHA256:" + base64.StdEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(fp), []byte(expectedFingerprint)) == 1, nil
}

// VerifySignature verifies an Ed25519 signature given a base64-encoded public key,
// the original message, and the base64-encoded signature.
func VerifySignature(pubKeyBase64 string, message []byte, sigBase64 string) (bool, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return false, fmt.Errorf("decode public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key length: %d", len(pubBytes))
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), message, sigBytes), nil
}
