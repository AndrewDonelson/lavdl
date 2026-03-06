// Copyright (c) 2026 Nlaak Studios (https://nlaak.com)
// Author: Andrew Donelson (https://www.linkedin.com/in/andrew-donelson/)
//
// errors.go — sentinel error values shared across all LADL packages

// Package errors defines the sentinel errors for the ladl service.
package errors

import "errors"

var (
	// Identity errors
	// ErrIdentityNotFound is returned when no identity file exists for the user.
	ErrIdentityNotFound = errors.New("ladl: no identity found for this user; run 'ladl verify'")
	// ErrInsecurePermissions is returned when an identity file has permissions
	// that allow other users to read it.
	ErrInsecurePermissions = errors.New("ladl: identity file has insecure permissions")
	// ErrDecryptionFailed is returned when an encrypted backup cannot be decrypted.
	ErrDecryptionFailed = errors.New("ladl: failed to decrypt identity backup (wrong passphrase?)")
	// ErrIdentityExists is returned when an identity already exists and --force was not set.
	ErrIdentityExists = errors.New("ladl: identity already exists; use --force to overwrite")

	// Verification errors
	// ErrInvalidAgeGroup is returned when the supplied age group letter is not valid.
	ErrInvalidAgeGroup = errors.New("ladl: group must be a, b, c, or d (lowercase)")
	// ErrDOBNotFound is returned when OCR cannot locate a date-of-birth field.
	ErrDOBNotFound = errors.New("ladl: could not locate date of birth in document")
	// ErrOCRFailed is returned when the Tesseract subprocess fails.
	ErrOCRFailed = errors.New("ladl: OCR processing failed")
	// ErrTesseractNotFound is returned when the tesseract binary is not installed.
	ErrTesseractNotFound = errors.New("ladl: tesseract binary not found; install with: apt install tesseract-ocr")
	// ErrVCInvalidSignature is returned when a W3C VC issuer signature is invalid.
	ErrVCInvalidSignature = errors.New("ladl: verifiable credential signature is invalid")
	// ErrVCMissingAgeClaim is returned when a W3C VC does not contain an age claim.
	ErrVCMissingAgeClaim = errors.New("ladl: verifiable credential does not contain an age claim")

	// Response format errors
	// ErrInvalidTwoByteResponse is returned when a two-byte response string is malformed.
	ErrInvalidTwoByteResponse = errors.New("ladl: response must be exactly 2 bytes in format {group}{level}")

	// API errors
	// ErrRemoteRequestDenied is returned when a non-localhost request hits the local API.
	ErrRemoteRequestDenied = errors.New("ladl: local API only accepts requests from localhost")
	// ErrRateLimitExceeded is returned when a client exceeds the rate limit.
	ErrRateLimitExceeded = errors.New("ladl: rate limit exceeded")
	// ErrLedgerModeRequired is returned when a ledger-only endpoint is accessed in peer mode.
	ErrLedgerModeRequired = errors.New("ladl: this endpoint requires --ledger mode")

	// LADL errors (wrap Strata L4 errors)
	// ErrLADLUnavailable is returned when the LADL network is unreachable.
	ErrLADLUnavailable = errors.New("ladl: LADL is unreachable; record saved locally, will sync when available")
	// ErrLADLRecordRevoked is returned when querying a revoked UUID.
	ErrLADLRecordRevoked = errors.New("ladl: this UUID has been revoked on the LADL")
)
