package golibsecp256k1

import "errors"

// Errors shared by both backends. Every function returns the same error, compared with
// errors.Is and by its text, for the same bad input whichever backend is compiled in.
// The semantics follow libsecp256k1: a secret key must be in [1, n-1], a multiplicative
// tweak must be in [1, n-1], an additive tweak must be in [0, n-1].
var (
	// ErrInvalidPubKey indicates a 33-byte input that is not a valid compressed point.
	ErrInvalidPubKey = errors.New("invalid public key")

	// ErrPointAtInfinity indicates that a point sum is the point at infinity (P + (-P)).
	//
	// Its text keeps the substring "not on secp256k1 curve": blindbit-oracle classifies a
	// transaction whose input keys sum to infinity as "skip" by matching that substring,
	// which the pure-Go backend has always produced for this case. Do not reword it.
	ErrPointAtInfinity = errors.New("point at infinity: result is not on secp256k1 curve")

	// ErrInvalidSecKey indicates a secret key that is zero or not below the group order n.
	ErrInvalidSecKey = errors.New("invalid secret key: zero or not below the group order")

	// ErrInvalidTweak indicates a tweak outside the range the operation accepts.
	ErrInvalidTweak = errors.New("invalid tweak: out of range")

	// ErrZeroResult indicates that a secret key tweak would produce the zero key.
	ErrZeroResult = errors.New("resulting secret key is zero")

	// ErrTweak indicates a secret key tweak (SecKeyAdd, MultPrivateKeys) failure. The
	// returned error also matches the specific cause (ErrInvalidSecKey, ErrInvalidTweak,
	// ErrZeroResult) under errors.Is.
	ErrTweak = errors.New("tweak operation failed")

	// ErrPubKeyTweakMul indicates a PubKeyTweakMul failure. The returned error also
	// matches the specific cause (ErrInvalidPubKey, ErrInvalidTweak) under errors.Is.
	ErrPubKeyTweakMul = errors.New("failed to tweak public key")
)

// opError ties an operation's error to its cause so that errors.Is matches both.
type opError struct{ op, cause error }

func (e *opError) Error() string   { return e.op.Error() + ": " + e.cause.Error() }
func (e *opError) Unwrap() []error { return []error{e.op, e.cause} }

func wrapErr(op, cause error) error { return &opError{op: op, cause: cause} }
