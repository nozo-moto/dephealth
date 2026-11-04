package main

import (
	"reflect"
	"testing"
)

func TestReorderArgs(t *testing.T) {
	got, err := reorderArgs([]string{".", "--fail-on", "none", "--direct", "web"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--fail-on", "none", "--direct", ".", "web"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
	if _, err := reorderArgs([]string{"--min-score"}); err == nil {
		t.Fatal("missing value should fail")
	}
}
