package proto

import "testing"

func TestLooksLikeHTTP(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"POST /wls-wsat/CoordinatorPortType HTTP/1.1", true},
		{"GET /solr HTTP/1.1", true},
		{"M-SEARCH * HTTP/1.1", true},
		{"t3 12.2.1\nAS:255\nHL:19", false},
		{"\x16\x03\x01\x01\"\x01\x00", false},
		{"hello world", false},
	}
	for _, c := range cases {
		if got := looksLikeHTTP([]byte(c.in)); got != c.want {
			t.Errorf("looksLikeHTTP(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
