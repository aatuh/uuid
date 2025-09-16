# uuid

A tiny Go helper for RFC 4122 UUID Version 4 (random) with Variant 1.
Provides secure generation, parsing/validation, and a zero UUID helper.

## Install

Import the package; `go get` will resolve the module automatically:

```go
import "github.com/aatuh/uuid"
```

### Quick start

```go
u, err := uuid.Ver4Var1()
if err != nil { /* handle */ }
fmt.Println(u.String())

u2 := uuid.MustVer4Var1()
fmt.Println(u2)
```

### Parse and validate

```go
u, err := uuid.Ver4Var1FromString("6f1a0b1c-8d7e-4a2b-8c9d-1e2f3a4b5c6d")
if err != nil { /* invalid */ }

if uuid.IsValid("not-a-uuid") {
    // never reached
}
```

### Zero UUID

Returns a value of canonical zero UUID with v4/variant bits set:

```go
z := uuid.Zero()
fmt.Println(z.String())
// 00000000-0000-4000-8000-000000000000
```

### API

- `type UUID string`
- `Ver4Var1() (UUID, error)`
- `MustVer4Var1() UUID`
- `Ver4Var1FromString(s string) (UUID, error)`
- `MustVer4Var1FromString(s string) *UUID`
- `Zero() *UUID`
- `IsValid(s string) bool`

### Notes

- Output format is `8-4-4-4-12` hex with the third block starting with
  `4` (version 4) and the fourth block starting with one of `8,9,A,B`
  (variant 1).
- Uses `crypto/rand` for variant selection and secure hex generation.
