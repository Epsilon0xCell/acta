// conformance: the Go conformance runner for the shared fixture
// corpus. It consumes the same canonical fixture files as the
// Python and Rust runners (see ../../CORPUS-INDEX.md) and reports
// each fixture by name with a summary line.
//
// Usage: conformance FIXTURES_DIR SECRET_FILE
//
// Author: Gavin Blacklock
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"acta-go/internal/acta"
	"acta-go/internal/canon"
	"acta-go/internal/institutio"
)

var secret []byte

func runFixture(path string) (bool, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err.Error()
	}
	doc, err := canon.Parse(data)
	if err != nil {
		return false, "fixture does not parse: " + err.Error()
	}
	kind := doc.Get("kind").StrOr("")
	name := filepath.Base(path)
	switch kind {
	case "receipt_bundle":
		return checkBundle(doc)
	case "standing":
		return checkStanding(doc)
	case "checkpoint":
		return checkCheckpoint(doc)
	case "charter":
		err := institutio.ValidateCharterStructure(doc.Get("charter"))
		return expectVerdict(doc, err)
	case "charter_chain":
		list := doc.Get("charters")
		var charters []*canon.Value
		if list != nil {
			charters = list.Arr
		}
		err := institutio.ValidateCharterChain(charters)
		return expectVerdict(doc, err)
	}
	return false, name + ": unknown fixture kind " + kind
}

func expectVerdict(doc *canon.Value, err error) (bool, string) {
	want := doc.Get("expected_verdict").StrOr("")
	if want == "valid" {
		if err != nil {
			return false, "expected valid, got " + err.Error()
		}
		return true, "valid as expected"
	}
	if err == nil {
		return false, "expected invalid, but it validated"
	}
	contains := doc.Get("expected_error_contains").StrOr("")
	if contains != "" && !strings.Contains(err.Error(), contains) {
		return false, fmt.Sprintf("error %q does not contain %q", err.Error(), contains)
	}
	return true, "rejected as expected: " + err.Error()
}

func checkBundle(doc *canon.Value) (bool, string) {
	receipts := doc.Get("bundle").Get("receipts")
	ver := &acta.HMACVerifier{ID: "acta-test-key-1", Secret: secret}
	_, err := acta.VerifyChain(receipts, ver, doc.Get("verify_expected_head").StrOr(""), 0)
	want := doc.Get("expected_verdict").StrOr("")
	if want == "valid" {
		if err != nil {
			return false, "expected valid chain, got " + err.Error()
		}
		if lr := doc.Get("expected_last_receipt"); lr != nil && receipts != nil && len(receipts.Arr) > 0 {
			last := receipts.Arr[len(receipts.Arr)-1]
			if last.Get("receipt_type").StrOr("") != lr.Get("receipt_type").StrOr("") ||
				last.Get("reason_code").StrOr("") != lr.Get("reason_code").StrOr("") {
				return false, "last receipt does not match the expected last receipt"
			}
		}
		return true, "chain verified as expected"
	}
	if err == nil {
		return false, "expected rejection, but the chain verified"
	}
	if ae, ok := err.(*acta.Error); ok {
		if code := doc.Get("expected_code").StrOr(""); code != "" && ae.Code != code {
			return false, fmt.Sprintf("expected code %s, got %s (%s)", code, ae.Code, ae.Msg)
		}
	}
	return true, "rejected as expected: " + err.Error()
}

func standingResult(doc *canon.Value) (map[string]*institutio.ClassResult, error) {
	var eval *int64
	if ev := doc.Get("eval_time"); ev != nil && ev.Kind == canon.KindInt {
		n := ev.Int
		eval = &n
	}
	return institutio.ComputeStanding(doc.Get("receipts"), doc.Get("standing_policy"), eval, doc.Get("agent_id").StrOr(""), nil)
}

func checkStanding(doc *canon.Value) (bool, string) {
	res, err := standingResult(doc)
	if err != nil {
		return false, "computation failed: " + err.Error()
	}
	exp := doc.Get("expected_standing")
	for _, class := range exp.Keys {
		got, ok := res[class]
		if !ok {
			return false, "no result for expected scope class " + class
		}
		gotVal := got.Value()
		for _, field := range exp.Obj[class].Keys {
			want := exp.Obj[class].Obj[field]
			if !canon.Equal(gotVal.Get(field), want) {
				return false, fmt.Sprintf("class %s field %s: expected %s, got %s", class, field, canon.Encode(want), canon.Encode(gotVal.Get(field)))
			}
		}
	}
	return true, "spec conformance: ComputeStanding over the fixture policy as written reproduces the expected Standing"
}

func checkCheckpoint(doc *canon.Value) (bool, string) {
	pol, err := institutio.ParsePolicy(doc.Get("standing_policy"))
	if err != nil {
		return expectVerdict(doc, err)
	}
	vers := map[string]acta.Verifier{}
	if pol.Witness != nil {
		for _, id := range pol.Witness.KeyIDs {
			vers[id] = &acta.HMACVerifier{ID: id, Secret: secret}
		}
	}
	if sig := doc.Get("checkpoint").Get("checkpoint_sig"); sig != nil && sig.Kind == canon.KindObject {
		kid := sig.Get("key_id").StrOr("")
		vers[kid] = &acta.HMACVerifier{ID: kid, Secret: secret}
	}
	err = institutio.VerifyCheckpoint(doc.Get("checkpoint"), doc.Get("receipts"), doc.Get("standing_policy"), nil, vers)
	return expectVerdict(doc, err)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("usage: conformance FIXTURES_DIR SECRET_FILE")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Println("cannot read secret file:", err)
		os.Exit(2)
	}
	secret = []byte(strings.TrimSpace(string(data)))
	entries, err := filepath.Glob(filepath.Join(os.Args[1], "fixture_*.json"))
	if err != nil || len(entries) == 0 {
		fmt.Println("no fixtures found in", os.Args[1])
		os.Exit(2)
	}
	sort.Strings(entries)
	passed, failed := 0, 0
	for _, path := range entries {
		ok, msg := runFixture(path)
		if ok {
			passed++
			fmt.Printf("PASS %s: %s\n", filepath.Base(path), msg)
		} else {
			failed++
			fmt.Printf("FAIL %s: %s\n", filepath.Base(path), msg)
		}
	}
	fmt.Printf("fixtures: %d run, %d passed, %d failed, 0 skipped\n", len(entries), passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
