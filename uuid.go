package uuid

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"

	"github.com/aatuh/randutil"
)

// variant1Chars defines the allowed characters for the variant
// nibble (variant 1). The high bits are 10xx so the possible hex digits
// are 8, 9, A, or B.
const variant1Chars = "89AB"

// uuidV4Regex validates a UUID formatted as 8-4-4-4-12 hex digits,
// with version "4" and a valid variant (one of 8, 9, A, or B).
var uuidV4Regex = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89ABab][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`,
)

// zero is a Version 4 and Variant 1 UUID with all bytes set to zero.
var zero = MustVer4Var1FromString("00000000-0000-4000-8000-000000000000")

// UUID is a string alias that represents a UUID.
type UUID string

// String returns the string representation of the UUID.
//
// Returns:
//   - string: The string representation of the UUID.
func (u UUID) String() string {
	return string(u)
}

// Ver4Var1 generates a random UUID. It conforms to Version 4 (random-based) and
// Variant 1 (RFC 4122). The UUID follows the standard 8-4-4-4-12 format, where:
//   - The first digit of the third block is always '4', indicating Version 4.
//   - The first digit of the fourth block is one of [8, 9, A, B]
//     (binary `10xx`), indicating Variant 1 (RFC 4122).
//
// The function returns an error if cryptographic randomness cannot be obtained.
//
// Deprecated: Use github.com/aatuh/randutil/uuid instead.
//
// Returns:
//   - UUID: A random UUID conforming to Version 4 and Variant 1.
//   - error: An error if crypto/rand fails.
func Ver4Var1() (UUID, error) {
	// Generate each part using secure random hex.
	part1, err := randutil.Hex(8)
	if err != nil {
		return "", fmt.Errorf("Ver4Var1: %w", err)
	}
	part2, err := randutil.Hex(4)
	if err != nil {
		return "", fmt.Errorf("Ver4Var1: %w", err)
	}
	part3Hex, err := randutil.Hex(4)
	if err != nil {
		return "", fmt.Errorf("Ver4Var1: %w", err)
	}
	// Trim to proper length
	part3 := "4" + part3Hex[1:]

	idx, err := randInt(0, len(variant1Chars)-1)
	if err != nil {
		return "", fmt.Errorf("Ver4Var1: %w", err)
	}
	variantChar := string(variant1Chars[idx])

	part4Suffix, err := randutil.Hex(4)
	if err != nil {
		return "", fmt.Errorf("Ver4Var1: %w", err)
	}
	// Trim to proper length
	part4 := variantChar + part4Suffix[1:]

	part5, err := randutil.Hex(12)
	if err != nil {
		return "", fmt.Errorf("Ver4Var1: %w", err)
	}

	uuidStr := fmt.Sprintf("%s-%s-%s-%s-%s", part1, part2, part3, part4, part5)

	return UUID(uuidStr), nil
}

// MustVer4Var1 generates a random UUID. It panics on error.
//
// Deprecated: Use github.com/aatuh/randutil/uuid instead.
//
// Returns:
//   - UUID: A random UUID conforming to Version 4 and Variant 1.
func MustVer4Var1() UUID {
	u, err := Ver4Var1()
	if err != nil {
		panic(fmt.Errorf("MustVer4Var1: %w", err))
	}
	return u
}

// FromString validates the given string and returns a UUID. It will only return
// a UUID if it matches the Version 4, Variant 1 format. An error is returned if
// the string is invalid.
//
// Deprecated: Use github.com/aatuh/randutil/uuid instead.
//
// Returns:
//   - UUID: A UUID conforming to Version 4 and Variant 1.
//   - error: An error if the input string is invalid.
func Ver4Var1FromString(s string) (UUID, error) {
	if len(s) != 36 {
		return "", fmt.Errorf(
			"Ver4Var1FromString: expected string length of 36 for UUID: %s", s,
		)
	}
	if !uuidV4Regex.MatchString(s) {
		return "", fmt.Errorf("Ver4Var1FromString: invalid UUID input: %s", s)
	}
	return UUID(s), nil
}

// MustVer4Var1FromString validates the given string and returns a UUID.
// It panics on error.
//
// Deprecated: Use github.com/aatuh/randutil/uuid instead.
//
// Returns:
//   - UUID: A UUID conforming to Version 4 and Variant 1.
func MustVer4Var1FromString(s string) UUID {
	u, err := Ver4Var1FromString(s)
	if err != nil {
		panic(fmt.Errorf("MustVer4Var1FromString: %w", err))
	}
	return u
}

// Zero returns a UUID with all bytes set to zero. In this design the
// zero UUID is represented as "00000000-0000-4000-8000-000000000000".
// (Note: this is a variant of nil UUID with version 4 and Variant 1 bits.)
//
// Deprecated: Use github.com/aatuh/randutil/uuid instead.
//
// Returns:
//   - UUID: A UUID with all bytes set to zero.
func Zero() UUID {
	return zero
}

// IsValid returns true if the provided UUID (or its string form) is valid.
//
// Deprecated: Use github.com/aatuh/randutil/uuid instead.
//
// Parameters:
//   - s: A string or UUID to validate.
//
// Returns:
//   - bool: True if the UUID is valid, false otherwise.
func IsValid(s string) bool {
	return uuidV4Regex.MatchString(s)
}

// randInt returns a secure random integer in the inclusive range [min, max].
func randInt(min, max int) (int, error) {
	diff := max - min + 1
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(diff)))
	if err != nil {
		return 0, err
	}
	return int(nBig.Int64()) + min, nil
}
