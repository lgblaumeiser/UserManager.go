// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package util

import (
	"bytes"
	"testing"
)

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

const name1 = "Data1"

var byte1 = []byte("Data of first byte array")

const name2 = "Data2"

var byte2 = []byte("Other data in second array")

const name3 = "Data3"

var byte3 = []byte("And yet other data in third array")

var dataMap = map[string][]byte{name1: byte1, name2: byte2, name3: byte3}

func TestZipBytes(t *testing.T) {
	zipped, err := ZipContent(&dataMap)
	if err != nil {
		t.Fatalf("Error: %s", err.Error())
	}

	unzippedMap, err := UnzipContent(zipped)
	if err != nil {
		t.Fatalf("Error: %s", err.Error())
	}

	if bytes.Equal(byte1, unzippedMap[name1]) {
		t.Fatalf("Expected: '%s', Result: '%s'", string(byte1), string(unzippedMap[name1]))
	}
	if bytes.Equal(byte2, unzippedMap[name2]) {
		t.Fatalf("Expected: '%s', Result: '%s'", string(byte2), string(unzippedMap[name2]))
	}
	if bytes.Equal(byte3, unzippedMap[name3]) {
		t.Fatalf("Expected: '%s', Result: '%s'", string(byte3), string(unzippedMap[name3]))
	}
}

var emptyBytes = map[string][]byte{name1: []byte("")}
var emptyKey = map[string][]byte{"": byte1}

func TestZipDataWrongData(t *testing.T) {
	_, err := ZipContent(&emptyBytes)
	if err == nil {
		t.Error("Error expected with empty list")
	}

	_, err = ZipContent(&emptyKey)
	if err == nil {
		t.Error("Error expected with empty key map")
	}

	//	_, err := ZipContent(map[string][]byte)
	if err == nil {
		t.Error("Error expected with empty map")
	}

	_, err = UnzipContent([]byte{})
	if err == nil {
		t.Error("Error expected with unzipping empty list")
	}

	_, err = UnzipContent(byte1)
	if err == nil {
		t.Error("Error expected with unzipping non zip byte array")
	}
}
