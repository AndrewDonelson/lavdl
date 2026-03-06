// Copyright (c) 2026 Nlaak Studios (https://nlaak.com)
// Author: Andrew Donelson (https://www.linkedin.com/in/andrew-donelson/)
//
// sign.go — payload signing helpers — builds and signs the canonical LADL record

package verification

import (
"crypto/ed25519"
"encoding/base64"
"fmt"

"github.com/AndrewDonelson/ladl/internal/format"
)

// signPayload signs the canonical two-byte response with the user's private key.
// It concatenates the UUID and the TwoByteResponse, then produces an Ed25519
// signature, returned as a base64url-encoded string.
func signPayload(priv ed25519.PrivateKey, uuid string, p format.VerificationPayload) (string, error) {
if priv == nil {
return "", fmt.Errorf("nil private key")
}
twoBytes := format.FormatTwoBytes(p)
msg := []byte(uuid + ":" + string(twoBytes))
sig := ed25519.Sign(priv, msg)
return base64.RawURLEncoding.EncodeToString(sig), nil
}
