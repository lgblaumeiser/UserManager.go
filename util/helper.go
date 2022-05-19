// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package util

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
)

const RoleSeparator = ";"

func IsCleanString(raw string) bool {
	return len(raw) > 0 && len(raw) == len(strings.TrimSpace(raw))
}

var isAlphaNumeric = regexp.MustCompile(`^[A-Za-z0-9-_.]+$`).MatchString

func IsCleanAlphanumericString(raw string) bool {
	return len(raw) > 0 && isAlphaNumeric(raw)
}

func TwoStringListsHaveSameContent(left *[]string, right *[]string) bool {
	if len(*left) != len(*right) {
		return false
	}

	for _, item := range *left {
		if !Contains(right, item) {
			return false
		}
	}

	return true
}

func Contains(list *[]string, content string) bool {
	for _, item := range *list {
		if item == content {
			return true
		}
	}
	return false
}

func ZipContent(data *map[string][]byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	zipWriter := zip.NewWriter(buf)

	for key, data := range *data {
		if !IsCleanString(key) || len(data) == 0 {
			return []byte{}, errors.New("Empty key or data not allowed")
		}
		zipFile, err := zipWriter.Create(fmt.Sprintf("%s.user", key))
		if err != nil {
			return []byte{}, err
		}
		_, err = zipFile.Write(data)
		if err != nil {
			return []byte{}, err
		}
	}

	err := zipWriter.Close()
	if err != nil {
		return []byte{}, err
	}

	return buf.Bytes(), nil
}

func UnzipContent(zipdata []byte) (map[string][]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipdata), int64(len(zipdata)))
	if err != nil {
		return nil, err
	}

	restoredData := map[string][]byte{}
	for _, file := range reader.File {
		fRef, zerr := file.Open()
		if zerr != nil {
			return nil, zerr
		}
		defer fRef.Close()

		content, zerr := ioutil.ReadAll(fRef)
		if zerr != nil {
			return nil, zerr
		}
		restoredData[file.Name] = content
	}

	return restoredData, nil
}
