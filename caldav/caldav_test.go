package caldav

import "testing"

func TestParseCalendarPath(t *testing.T) {
	cases := []struct {
		in      string
		wantID  string
		wantErr bool
	}{
		{in: "/calendar/abc123", wantID: "abc123"},
		{in: "/calendar/abc123/", wantID: "abc123"},
		{in: "/calendar/", wantErr: true},
		{in: "/calendar", wantErr: true},
		{in: "/contacts/default", wantErr: true},
		{in: "/", wantErr: true},
		{in: "", wantErr: true},
		{in: "/calendar/abc/def", wantErr: true}, // object path, not calendar path
	}

	for _, c := range cases {
		got, err := parseCalendarPath(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseCalendarPath(%q): expected error, got id=%q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseCalendarPath(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.wantID {
			t.Errorf("parseCalendarPath(%q): got %q, want %q", c.in, got, c.wantID)
		}
	}
}

func TestParseCalendarObjectPath(t *testing.T) {
	cases := []struct {
		in             string
		wantCalendarID string
		wantEventID    string
		wantErr        bool
	}{
		{in: "/calendar/abc123/def456.ics", wantCalendarID: "abc123", wantEventID: "def456"},
		{in: "/calendar/abc/def.txt", wantErr: true}, // wrong ext
		{in: "/calendar/abc/def", wantErr: true},     // no ext
		{in: "/calendar/abc/", wantErr: true},        // no filename
		{in: "/calendar/", wantErr: true},
		{in: "/contacts/default/x.vcf", wantErr: true}, // wrong prefix
		{in: "/", wantErr: true},
		{in: "", wantErr: true},
	}

	for _, c := range cases {
		gotCal, gotEv, err := parseCalendarObjectPath(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseCalendarObjectPath(%q): expected error, got cal=%q ev=%q", c.in, gotCal, gotEv)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseCalendarObjectPath(%q): unexpected error: %v", c.in, err)
			continue
		}
		if gotCal != c.wantCalendarID || gotEv != c.wantEventID {
			t.Errorf("parseCalendarObjectPath(%q): got (%q,%q), want (%q,%q)",
				c.in, gotCal, gotEv, c.wantCalendarID, c.wantEventID)
		}
	}
}

func TestFormatPaths(t *testing.T) {
	if got := formatCalendarPath("abc"); got != "/calendar/abc" {
		t.Errorf("formatCalendarPath: got %q", got)
	}
	if got := formatCalendarObjectPath("abc", "def"); got != "/calendar/abc/def.ics" {
		t.Errorf("formatCalendarObjectPath: got %q", got)
	}
}
