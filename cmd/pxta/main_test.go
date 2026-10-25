package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/softdevstudio/pxta"
)

func TestCLI(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 || out.String() != "pxta "+pxta.Version+"\n" {
		t.Errorf("version: %d %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"catalog"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "meta-pixel") || !strings.Contains(out.String(), "10 trackers") {
		t.Errorf("catalog: %d %q", code, out.String())
	}
	errb.Reset()
	if code := run(nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "Usage") {
		t.Errorf("no args: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"bogus"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "unknown command") {
		t.Errorf("unknown: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"audit"}, &out, &errb); code != 2 {
		t.Errorf("audit without a URL: %d", code)
	}
	errb.Reset()
	if code := run([]string{"audit", "https://example.com", "--passes", "maybe"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "unknown pass") {
		t.Errorf("bad pass: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"audit", "ftp://example.com"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "http(s)") {
		t.Errorf("bad scheme: %d %q", code, errb.String())
	}
}
