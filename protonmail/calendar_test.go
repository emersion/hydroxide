package protonmail

import (
	"errors"
	"fmt"
	"testing"
)

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
