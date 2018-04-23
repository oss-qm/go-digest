// Copyright 2017 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package digest

import (
	"bytes"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"flag"
	"fmt"
	"testing"
)

func TestFlagInterface(t *testing.T) {
	var (
		alg     Algorithm
		flagSet flag.FlagSet
	)

	flagSet.Var(&alg, "algorithm", "set the digest algorithm")
	for _, testcase := range []struct {
		Name     string
		Args     []string
		Err      error
		Expected Algorithm
	}{
		{
			Name: "Invalid",
			Args: []string{"-algorithm", "bean"},
			Err:  ErrDigestUnsupported,
		},
		{
			Name:     "Default",
			Args:     []string{"unrelated"},
			Expected: "sha256",
		},
		{
			Name:     "Other",
			Args:     []string{"-algorithm", "sha512"},
			Expected: "sha512",
		},
	} {
		fmt.Println("test disabled for go-1.8 compat: ", testcase.Name)
	}
}

func TestFroms(t *testing.T) {
	p := make([]byte, 1<<20)
	rand.Read(p)

	for alg := range algorithms {
		h := alg.Hash()
		h.Write(p)
		expected := Digest(fmt.Sprintf("%s:%x", alg, h.Sum(nil)))
		readerDgst, err := alg.FromReader(bytes.NewReader(p))
		if err != nil {
			t.Fatalf("error calculating hash from reader: %v", err)
		}

		dgsts := []Digest{
			alg.FromBytes(p),
			alg.FromString(string(p)),
			readerDgst,
		}

		if alg == Canonical {
			readerDgst, err := FromReader(bytes.NewReader(p))
			if err != nil {
				t.Fatalf("error calculating hash from reader: %v", err)
			}

			dgsts = append(dgsts,
				FromBytes(p),
				FromString(string(p)),
				readerDgst)
		}
		for _, dgst := range dgsts {
			if dgst != expected {
				t.Fatalf("unexpected digest %v != %v", dgst, expected)
			}
		}
	}
}
