package protonmail

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// TestAttendeeToken pins the Proton attendee-token derivation: SHA1(UID +
// lowercased/trimmed email) as 40-char hex (mirrors WebClients
// generateAttendeeToken). A wrong token means Proton can't match the invitee.
func TestAttendeeToken(t *testing.T) {
	uid := "abc-123@proton.me"
	want := func(email string) string {
		sum := sha1.Sum([]byte(uid + email))
		return hex.EncodeToString(sum[:])
	}

	tok := attendeeToken(uid, "Friend@Example.COM")
	if len(tok) != 40 {
		t.Fatalf("token length = %d, want 40", len(tok))
	}
	if tok != want("friend@example.com") {
		t.Fatalf("token = %s, want SHA1(uid+lowercased email)", tok)
	}
	// Case/whitespace in the email must not change the token.
	if attendeeToken(uid, "  friend@example.com ") != tok {
		t.Fatal("token should be invariant to surrounding whitespace and case")
	}
	// Different email => different token.
	if attendeeToken(uid, "other@example.com") == tok {
		t.Fatal("different emails must produce different tokens")
	}
}

// TestIsEventNotFoundErr guards the create-vs-update detection in
// UpdateCalendarEvent. GetCalendarEvent wraps its APIError with
// fmt.Errorf("...%w..."), which a bare `err.(*APIError)` type assertion does
// NOT see through — that regression made every CalDAV event creation fail with
// a 500. isEventNotFoundErr must unwrap via errors.As.
func TestIsEventNotFoundErr(t *testing.T) {
	notFound := &APIError{Code: calendarEventNotFoundCode, Message: "Attribute EventID is invalid"}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"bare not-found APIError", notFound, true},
		{
			"wrapped not-found APIError (real GetCalendarEvent path)",
			fmt.Errorf("GetCalendarEvent: failed: (%w)", notFound),
			true,
		},
		{
			"doubly wrapped not-found APIError",
			fmt.Errorf("outer: (%w)", fmt.Errorf("inner: (%w)", notFound)),
			true,
		},
		{
			"different API error code",
			&APIError{Code: 33101, Message: "The Email is required"},
			false,
		},
		{
			"wrapped different API error code",
			fmt.Errorf("wrap: (%w)", &APIError{Code: 33101}),
			false,
		},
		{"non-API error", errors.New("network down"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isEventNotFoundErr(tc.err); got != tc.want {
				t.Fatalf("isEventNotFoundErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
