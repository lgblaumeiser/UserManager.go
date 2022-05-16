// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package functions

import "testing"

func TestIsCleanString(t *testing.T) {
	if !IsCleanString("&fsdlj2/tf") {
		t.Errorf("string check failed")
	}

	if IsCleanString("") {
		t.Errorf("string check failed")
	}

	if IsCleanString("\t") {
		t.Errorf("string check failed")
	}

	if IsCleanString("\n") {
		t.Errorf("string check failed")
	}

	if IsCleanString("\t   ksdjf9") {
		t.Errorf("string check failed")
	}

	if IsCleanString("jkasdhf8&837\n") {
		t.Errorf("string check failed")
	}
}

func TestIsAlphanumericString(t *testing.T) {
	if !IsCleanAlphanumericString("aBZ7_.78-gT") {
		t.Errorf("string check failed")
	}

	if !IsCleanAlphanumericString("_aBZ7gT") {
		t.Errorf("string check failed")
	}

	if IsCleanAlphanumericString("a$6783") {
		t.Errorf("string check failed")
	}

	if IsCleanAlphanumericString("  6dfahkj") {
		t.Errorf("string check failed")
	}
}

func TestTwoStringListsHaveSameContent(t *testing.T) {
	list1 := []string{"one", "two", "three"}
	list2 := []string{"three", "two", "one"}
	list3 := []string{"three", "four", "five"}

	if !TwoStringListsHaveSameContent(&list1, &list1) {
		t.Errorf("list check failed")
	}

	if !TwoStringListsHaveSameContent(&list1, &list2) {
		t.Errorf("list check failed")
	}

	if TwoStringListsHaveSameContent(&list1, &list3) {
		t.Errorf("list check failed")
	}
}

func TestContains(t *testing.T) {
	list1 := []string{"one", "two", "three"}

	if !Contains(&list1, "one") {
		t.Errorf("list check failed")
	}

	if Contains(&list1, "four") {
		t.Errorf("list check failed")
	}
}
