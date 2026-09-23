package handlers

import "testing"

// The real node names are not uniform, so the renaming rule is exercised
// against the shapes that actually exist in the database.
func TestRenameForCountry(t *testing.T) {
	cases := []struct {
		name    string
		country string
		want    string
		why     string
	}{
		{"ash-one-C-A-142", "DE", "de-one-C-A-142",
			"a datacenter code is replaced and the trailing number kept"},
		{"AshOne-C-AA-135", "DE", "de-AshOne-C-AA-135",
			"no separator after a place token, so the country is only prefixed"},
		{"fi 9-166", "DE", "de-9-166",
			"a two-letter country code is replaced, whatever the separator"},
		{"hel1-node-7", "FI", "fi-node-7",
			"a numbered datacenter code is recognised"},
		{"Back-Ash-38", "FI", "fi-Back-Ash-38",
			"a leading word that is not a place is left alone"},
		{"de-one-C-A-142", "DE", "de-one-C-A-142",
			"a node already named for its country is untouched"},
		{"", "DE", "", "an empty name stays empty"},
		{"node-1", "", "node-1", "without a country nothing changes"},
	}

	for _, tc := range cases {
		if got := renameForCountry(tc.name, tc.country); got != tc.want {
			t.Errorf("renameForCountry(%q, %q) = %q, want %q — %s",
				tc.name, tc.country, got, tc.want, tc.why)
		}
	}
}

// The original name is kept in tags, so a bad guess by the renaming rule never
// loses what the operator chose.
func TestMergeTags(t *testing.T) {
	cases := []struct{ tags, add, want string }{
		{"", "was:ash-1", "was:ash-1"},
		{"fast", "was:ash-1", "fast,was:ash-1"},
		{"was:ash-1", "was:ash-1", "was:ash-1"},
		{"fast,was:ash-1", "was:ash-1", "fast,was:ash-1"},
		{"fast", "", "fast"},
	}
	for _, tc := range cases {
		if got := mergeTags(tc.tags, tc.add); got != tc.want {
			t.Errorf("mergeTags(%q, %q) = %q, want %q", tc.tags, tc.add, got, tc.want)
		}
	}
}

func TestParseActive(t *testing.T) {
	cases := []struct {
		in   string
		def  bool
		want bool
	}{
		{"true", false, true},
		{"false", true, false},
		{"1", false, true},
		{"0", true, false},
		{"", true, true},    // absent means "use the default"
		{"", false, false},  // which for a toggle is the flipped value
		{"garbage", true, true},
	}
	for _, tc := range cases {
		if got := parseActive(tc.in, tc.def); got != tc.want {
			t.Errorf("parseActive(%q, %v) = %v, want %v", tc.in, tc.def, got, tc.want)
		}
	}
}
