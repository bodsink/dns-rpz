package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// generateRSAKeypair generates a 2048-bit RSA keypair.
func generateRSAKeypair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// privateKeyToPEM encodes an RSA private key to PKCS#8 PEM bytes.
func privateKeyToPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8 private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// publicKeyToPEM encodes an RSA public key to PKIX PEM bytes.
func publicKeyToPEM(key *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal pkix public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// encryptPrivateKey encrypts PEM bytes using AES-256-GCM.
// hexKey must be a 64-char hex string (32 bytes).
// Output format: base64(nonce || ciphertext+tag).
func encryptPrivateKey(pemBytes []byte, hexKey string) (string, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != 32 {
		return "", fmt.Errorf("KEY_ENCRYPTION_KEY must be a 64-char hex string (32 bytes)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	// Seal appends ciphertext+tag to nonce
	ciphertext := gcm.Seal(nonce, nonce, pemBytes, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptPrivateKey decrypts an AES-256-GCM encrypted private key from DB.
func decryptPrivateKey(enc string, hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("KEY_ENCRYPTION_KEY must be a 64-char hex string (32 bytes)")
	}
	data, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// generateJTI generates a cryptographically secure random 32-byte JWT ID.
func generateJTI() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// APITokenClaims holds the JWT claims used for REST API authentication.
type APITokenClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// signAPIToken creates a JWT signed with the user's RSA-2048 private key (RS256).
func signAPIToken(privateKeyPEM []byte, userID int64, jti, role string, expiresAt time.Time) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("parse rsa private key: %w", err)
	}
	claims := APITokenClaims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(userID, 10),
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(key)
}

// verifyAPIToken verifies a JWT using the user's RSA public key and returns the claims.
func verifyAPIToken(tokenString string, publicKeyPEM []byte) (*APITokenClaims, error) {
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse rsa public key: %w", err)
	}
	token, err := jwt.ParseWithClaims(tokenString, &APITokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*APITokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// parseUnverifiedJWT parses JWT claims without verifying the signature.
// Used to extract the subject (user_id) before fetching the public key.
func parseUnverifiedJWT(tokenString string) (jwt.Claims, jwt.MapClaims, error) {
	p := jwt.NewParser()
	claims := jwt.MapClaims{}
	token, _, err := p.ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, nil, err
	}
	return token.Claims, claims, nil
}
