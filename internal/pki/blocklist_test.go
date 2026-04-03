package pki

import (
	"testing"
)

func TestBlocklist_AddAndContains(t *testing.T) {
	bl := NewBlocklist()

	if bl.Contains("fp1") {
		t.Error("empty blocklist should not contain fp1")
	}

	bl.Add("fp1")
	if !bl.Contains("fp1") {
		t.Error("blocklist should contain fp1 after Add")
	}

	bl.Add("fp2")
	if !bl.Contains("fp2") {
		t.Error("blocklist should contain fp2 after Add")
	}
}

func TestBlocklist_Remove(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("fp1")
	bl.Add("fp2")

	bl.Remove("fp1")
	if bl.Contains("fp1") {
		t.Error("blocklist should not contain fp1 after Remove")
	}
	if !bl.Contains("fp2") {
		t.Error("blocklist should still contain fp2")
	}
}

func TestBlocklist_List(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("fp1")
	bl.Add("fp2")
	bl.Add("fp3")

	list := bl.List()
	if len(list) != 3 {
		t.Fatalf("List() len = %d, want 3", len(list))
	}

	found := make(map[string]bool)
	for _, fp := range list {
		found[fp] = true
	}
	for _, fp := range []string{"fp1", "fp2", "fp3"} {
		if !found[fp] {
			t.Errorf("List() missing %q", fp)
		}
	}
}

func TestBlocklist_DuplicateAdd(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("fp1")
	bl.Add("fp1")

	list := bl.List()
	if len(list) != 1 {
		t.Errorf("List() len = %d after duplicate Add, want 1", len(list))
	}
}

func TestBlocklist_RemoveNonexistent(t *testing.T) {
	bl := NewBlocklist()
	bl.Remove("nonexistent") // should not panic
}
