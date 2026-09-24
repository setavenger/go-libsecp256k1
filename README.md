# go-libsecp256k1

Compile go program with `-tags=libsecp256k1` to use C bindings. 
Benchmarks in BlindBit indicate potential speed ups of ~3x when using C bindings.

## Errors and invalid input

Both backends return the same errors for the same input (see `errors.go`); `parity_test.go`
runs unchanged under both builds to enforce it. Secret keys must be in `[1, n-1]`, additive
tweaks in `[0, n-1]`, multiplicative tweaks in `[1, n-1]`; a sum at the point at infinity
returns `ErrPointAtInfinity`. On error, in-place arguments are left unchanged.

The cgo backend checks every libsecp256k1 return code and validates arguments before use,
so no input reaches libsecp256k1's illegal-argument callback. As a second line of defence,
the context installs a callback that counts the call and returns instead of aborting the
process; the libsecp256k1 function then returns 0 and the wrapper reports an error.
