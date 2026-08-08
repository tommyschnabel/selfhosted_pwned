package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sha1 of "password", lowercase.
const passwordHash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"

func fakeRange(t *testing.T, body string, status int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/range/%s"
}

func usePwnedRange(t *testing.T, url string) {
	t.Helper()
	original := pwnedRangeURL
	pwnedRangeURL = url
	t.Cleanup(func() { pwnedRangeURL = original })
}

func TestHashPassword(t *testing.T) {
	if got := hashPassword("password"); got != passwordHash {
		t.Errorf("hashPassword = %q, want %q", got, passwordHash)
	}
}

func TestCheckHashInPwned(t *testing.T) {
	suffix := strings.ToUpper(passwordHash[5:])

	t.Run("returns the breach count for a match", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, suffix+":9659365\r\n", http.StatusOK))
		count, err := checkHashInPwned(passwordHash[:5], passwordHash)
		if err != nil {
			t.Fatalf("checkHashInPwned: %v", err)
		}
		if count != 9659365 {
			t.Errorf("count = %d, want 9659365", count)
		}
	})

	t.Run("returns zero when the suffix is absent", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, "0018A45C4D1DEF81644B54AB7F969B88D65:1\n", http.StatusOK))
		count, err := checkHashInPwned(passwordHash[:5], passwordHash)
		if err != nil {
			t.Fatalf("checkHashInPwned: %v", err)
		}
		if count != 0 {
			t.Errorf("count = %d, want 0", count)
		}
	})

	t.Run("a non-200 response is an error", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, "", http.StatusTooManyRequests))
		if _, err := checkHashInPwned(passwordHash[:5], passwordHash); err == nil {
			t.Fatal("expected an error for HTTP 429")
		}
	})

	t.Run("only the 5-char prefix is sent upstream", func(t *testing.T) {
		var requested string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requested = r.URL.Path
			fmt.Fprint(w, suffix+":1\n")
		}))
		t.Cleanup(srv.Close)
		usePwnedRange(t, srv.URL+"/range/%s")

		if _, err := checkHashInPwned(passwordHash[:5], passwordHash); err != nil {
			t.Fatalf("checkHashInPwned: %v", err)
		}
		if strings.Contains(requested, passwordHash[5:]) {
			t.Errorf("the full hash reached the network: %s", requested)
		}
		if requested != "/range/"+passwordHash[:5] {
			t.Errorf("requested %q, want /range/%s", requested, passwordHash[:5])
		}
	})
}
