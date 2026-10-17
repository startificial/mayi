package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServiceReplacementCanonicalizesParentAndRejectsEscape(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	inside := filepath.Join(source, "sdk")
	outside := filepath.Join(dir, "outside")
	for _, p := range []string{inside, outside} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(source, alias); err != nil {
		t.Fatal(err)
	}
	if !localServiceReplacement(alias, inside) {
		t.Fatal("canonical local replacement refused")
	}
	if localServiceReplacement(source, outside) {
		t.Fatal("external replacement accepted")
	}
	link := filepath.Join(source, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if localServiceReplacement(source, link) {
		t.Fatal("symlink escape accepted")
	}
}
