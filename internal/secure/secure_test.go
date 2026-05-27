package secure

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptSecretsRoundTripAndRejectsWrongMasterKey(t *testing.T) {
	plain := []byte(`{"ssh":{"prod":{"password":"secret"}}}`)

	encrypted, err := EncryptSecrets("correct horse battery staple", plain)
	if err != nil {
		t.Fatalf("EncryptSecrets returned error: %v", err)
	}
	if bytes.Contains(encrypted, []byte("secret")) {
		t.Fatalf("encrypted payload leaked plaintext secret: %s", string(encrypted))
	}

	decrypted, err := DecryptSecrets("correct horse battery staple", encrypted)
	if err != nil {
		t.Fatalf("DecryptSecrets returned error with correct master key: %v", err)
	}
	if !bytes.Equal(decrypted, plain) {
		t.Fatalf("decrypted payload mismatch\nwant: %s\n got: %s", plain, decrypted)
	}

	if _, err := DecryptSecrets("wrong master key", encrypted); err == nil {
		t.Fatalf("DecryptSecrets accepted a wrong master key")
	}
}

func TestMasterKeyVerifierAcceptsOnlyOriginalKey(t *testing.T) {
	verifier, err := NewMasterKeyVerifier("admin-secret")
	if err != nil {
		t.Fatalf("NewMasterKeyVerifier returned error: %v", err)
	}

	if !verifier.Verify("admin-secret") {
		t.Fatalf("verifier rejected the original master key")
	}
	if verifier.Verify("other-secret") {
		t.Fatalf("verifier accepted a different master key")
	}
}
