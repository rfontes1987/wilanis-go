// Package clock is the single named component permitted to read time
// (§11.19): one monotonic elapsed-time measurement, recorded about the run in
// the report's elapsed field, influencing nothing. The §15.12 architectural
// check enforces that no other kernel component imports a clock API.
package clock

import "time"

// Token is an opaque start mark.
type Token struct{ t time.Time }

// Start begins the single sanctioned elapsed-time measurement.
func Start() Token { return Token{t: time.Now()} }

// ElapsedMillis returns whole milliseconds since the token, never negative.
func ElapsedMillis(tok Token) int64 {
	ms := int64(time.Since(tok.t) / time.Millisecond)
	if ms < 0 {
		return 0
	}
	return ms
}
