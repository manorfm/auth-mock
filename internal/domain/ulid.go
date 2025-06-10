package domain

import (
	"fmt"

	"github.com/oklog/ulid/v2"
)

// ParseULID parses a string into a ULID
func ParseULID(id string) (ulid.ULID, error) {
	parsedID, err := ulid.Parse(id)
	if err != nil {
		return ulid.ULID{}, fmt.Errorf("invalid ULID: %w", err)
	}
	return parsedID, nil
}

// MustParseULID parses a string into a ULID and panics if the string is not a valid ULID
func MustParseULID(id string) ulid.ULID {
	parsedID, err := ParseULID(id)
	if err != nil {
		panic(err)
	}
	return parsedID
}
