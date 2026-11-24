// acta-verify: the one-file offline verifier (specification
// Section 4.1, ticket T3). One static binary, no network access,
// no keys beyond the ones the caller pins on the command line.
//
// Usage:
//
//	acta-verify BUNDLE.json --secret-file F --key-id ID [--expected-head HEX] [--expected-length N]
//	acta-verify BUNDLE.json --trust-file T.json [--expected-head HEX] [--expected-length N]
//	acta-verify standing CASE.json [--counterparty-keys KEYS.json]
//	acta-verify checkpoint CASE.json --secret-file F
//
// The first two forms verify a receipt bundle: the secret-file
// form is the legacy prototype path (HMAC placeholder signatures),
// the trust-file form is the native Ed25519 path with pinned keys
// from {"keys": [{"key_id": "...", "verifying_key_hex": "..."}]}.
// The standing form runs ComputeStanding over a case file of the
// fixture form {receipts, standing_policy, eval_time, agent_id,
// counterparty_keys} and prints the result as canonical JSON, or
// an ERROR line. The checkpoint form verifies a StandingCheckpoint
// case file {checkpoint, receipts, standing_policy}.
//
// Author: Gavin Blacklock
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"acta-go/internal/acta"
	"acta-go/internal/canon"
	"acta-go/internal/institutio"
)

func readValue(path string) (*canon.Value, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return canon.Parse(data)
}

func readSecret(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(string(data))), nil
}

func counterpartyKeys(v *canon.Value) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	if v == nil {
		return out, nil
	}
	for _, id := range v.Keys {
		kv := v.Obj[id]
		var hexStr string
		if kv.Kind == canon.KindString {
			hexStr = kv.Str
		} else if kv.Kind == canon.KindObject {
			hexStr = kv.Get("verifying_key_hex").StrOr("")
		}
		b, err := hex.DecodeString(hexStr)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("counterparty key %q is not a hex Ed25519 public key", id)
		}
		out[id] = ed25519.PublicKey(b)
	}
	return out, nil
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "standing" {
		os.Exit(runStanding(args[1:]))
	}
	if len(args) > 0 && args[0] == "validate-policy" {
		doc, err := readValue(positional(args[1:]))
		if err != nil {
			fmt.Println("ERROR: cannot parse policy file:", err)
			os.Exit(1)
		}
		if err := institutio.ValidateStandingPolicy(doc.Get("standing_policy")); err != nil {
			fmt.Println("ERROR:", err)
			os.Exit(1)
		}
		fmt.Println("PASS: standing policy valid")
		os.Exit(0)
	}
	if len(args) > 0 && args[0] == "checkpoint" {
		os.Exit(runCheckpoint(args[1:]))
	}
	os.Exit(runBundle(args))
}

func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func positional(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			return a
		}
	}
	return ""
}

func runBundle(args []string) int {
	path := positional(args)
	if path == "" {
		fmt.Println("FAIL: usage: acta-verify BUNDLE.json (--secret-file F --key-id ID | --trust-file T.json)")
		return 2
	}
	doc, err := readValue(path)
	if err != nil {
		fmt.Println("FAIL: cannot parse bundle:", err)
		return 1
	}
	receipts := doc.Get("receipts")
	if receipts == nil && doc.Get("bundle") != nil {
		receipts = doc.Get("bundle").Get("receipts")
	}
	if receipts == nil {
		fmt.Println("FAIL: bundle carries no receipts")
		return 1
	}
	var ver acta.Verifier
	if tf := flagValue(args, "--trust-file"); tf != "" {
		tv, err := readValue(tf)
		if err != nil {
			fmt.Println("FAIL: cannot parse trust file:", err)
			return 2
		}
		keys := tv.Get("keys")
		if keys == nil || len(keys.Arr) == 0 {
			fmt.Println("FAIL: trust file pins no keys")
			return 2
		}
		k0 := keys.Arr[0]
		pk, err := hex.DecodeString(k0.Get("verifying_key_hex").StrOr(""))
		if err != nil || len(pk) != ed25519.PublicKeySize {
			fmt.Println("FAIL: trust file key is not a hex Ed25519 public key")
			return 2
		}
		ver = &acta.Ed25519Verifier{ID: k0.Get("key_id").StrOr(""), Key: ed25519.PublicKey(pk)}
	} else if sf := flagValue(args, "--secret-file"); sf != "" {
		secret, err := readSecret(sf)
		if err != nil {
			fmt.Println("FAIL: cannot read secret file:", err)
			return 2
		}
		keyID := flagValue(args, "--key-id")
		if keyID == "" {
			keyID = "acta-test-key-1"
		}
		ver = &acta.HMACVerifier{ID: keyID, Secret: secret}
	} else {
		fmt.Println("FAIL: no pinned key: pass --secret-file (legacy) or --trust-file (native); the verifier fails closed")
		return 2
	}
	expectedLength := 0
	if s := flagValue(args, "--expected-length"); s != "" {
		fmt.Sscan(s, &expectedLength)
	}
	head, err := acta.VerifyChain(receipts, ver, flagValue(args, "--expected-head"), expectedLength)
	if err != nil {
		fmt.Println("FAIL:", err)
		return 1
	}
	fmt.Printf("PASS: chain verified, %d receipts, head %s\n", len(receipts.Arr), head)
	return 0
}

func runStanding(args []string) int {
	path := positional(args)
	doc, err := readValue(path)
	if err != nil {
		fmt.Println("ERROR: cannot parse case:", err)
		return 1
	}
	var eval *int64
	if ev := doc.Get("eval_time"); ev != nil && ev.Kind == canon.KindInt {
		n := ev.Int
		eval = &n
	}
	keys, err := counterpartyKeys(doc.Get("counterparty_keys"))
	if err != nil {
		fmt.Println("ERROR:", err)
		return 1
	}
	if kf := flagValue(args, "--counterparty-keys"); kf != "" {
		kv, err := readValue(kf)
		if err != nil {
			fmt.Println("ERROR: cannot parse counterparty keys:", err)
			return 1
		}
		keys, err = counterpartyKeys(kv)
		if err != nil {
			fmt.Println("ERROR:", err)
			return 1
		}
	}
	res, err := institutio.ComputeStanding(doc.Get("receipts"), doc.Get("standing_policy"), eval, doc.Get("agent_id").StrOr(""), keys)
	if err != nil {
		fmt.Println("ERROR:", err)
		return 1
	}
	fmt.Println(string(canon.Encode(institutio.ResultValue(res))))
	return 0
}

func runCheckpoint(args []string) int {
	path := positional(args)
	doc, err := readValue(path)
	if err != nil {
		fmt.Println("FAIL: cannot parse case:", err)
		return 1
	}
	sf := flagValue(args, "--secret-file")
	if sf == "" {
		fmt.Println("FAIL: checkpoint verification on the legacy path requires --secret-file")
		return 2
	}
	secret, err := readSecret(sf)
	if err != nil {
		fmt.Println("FAIL: cannot read secret file:", err)
		return 2
	}
	vers := map[string]acta.Verifier{}
	pol, err := institutio.ParsePolicy(doc.Get("standing_policy"))
	if err != nil {
		fmt.Println("FAIL:", err)
		return 1
	}
	if pol.Witness != nil {
		for _, id := range pol.Witness.KeyIDs {
			vers[id] = &acta.HMACVerifier{ID: id, Secret: secret}
		}
	}
	if sig := doc.Get("checkpoint").Get("checkpoint_sig"); sig != nil && sig.Kind == canon.KindObject {
		kid := sig.Get("key_id").StrOr("")
		vers[kid] = &acta.HMACVerifier{ID: kid, Secret: secret}
	}
	if err := institutio.VerifyCheckpoint(doc.Get("checkpoint"), doc.Get("receipts"), doc.Get("standing_policy"), nil, vers); err != nil {
		fmt.Println("FAIL:", err)
		return 1
	}
	fmt.Println("PASS: checkpoint verified by recomputation")
	return 0
}
