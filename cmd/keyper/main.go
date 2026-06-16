// Copyright 2024 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// keyper is the decryption-committee daemon for the encrypted mempool. A keyper
// holds one threshold key share and serves verifiable decryption shares to block
// proposers so encrypted-mempool transactions can be decrypted at inclusion.
//
// Subcommands:
//
//	keyper bootstrap -t <threshold> -n <keypers> -dir <out> -registry <addr>
//	    Generate a t-of-n committee by distributed key generation, writing one
//	    secret key file per keyper plus a committee.json (eon key + registry
//	    storage for genesis). DEVNET ONLY: a single operator running bootstrap holds
//	    the whole committee, which provides no threshold trust. A real committee runs
//	    the per-party DKG across independent operators.
//
//	keyper serve -key <keyfile> -addr <listen> [-auth <token>] [-disabled]
//	    Load a key file and serve decryption shares over HTTP. Release is gated by
//	    the auth token (only proposers presenting it are served) and the enable
//	    trigger (on unless -disabled; toggle in code/ops). These controls stop
//	    arbitrary parties from decrypting the encrypted mempool.
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/keyper/keypernet"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "bootstrap":
		bootstrap(os.Args[2:])
	case "serve":
		serve(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: keyper <bootstrap|serve> [flags]")
	fmt.Fprintln(os.Stderr, "  bootstrap  generate a devnet committee (DKG)")
	fmt.Fprintln(os.Stderr, "  serve      run a keyper, serving decryption shares over HTTP")
}

func bootstrap(args []string) {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	t := fs.Int("t", 0, "decryption threshold")
	n := fs.Int("n", 0, "number of keypers")
	dir := fs.String("dir", "keyper-committee", "output directory")
	registry := fs.String("registry", "", "keyper registry account address (0x...)")
	fs.Parse(args)

	if *t < 1 || *n < *t {
		fatalf("invalid -t/-n: need 1 <= t <= n")
	}
	if !common.IsHexAddress(*registry) {
		fatalf("invalid -registry address")
	}
	registryAddr := common.HexToAddress(*registry)

	keypers, mpk, _, err := keypernet.Bootstrap(*t, *n, rand.Reader)
	if err != nil {
		fatalf("dkg: %v", err)
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fatalf("mkdir: %v", err)
	}
	// Devnet keyper identity addresses are placeholders derived from the index; a
	// production registry records the keypers' real on-chain identities.
	keyperAddrs := make([]common.Address, *n)
	for i, k := range keypers {
		keyperAddrs[i] = common.BytesToAddress([]byte{byte(k.Index())})
		path := filepath.Join(*dir, fmt.Sprintf("keyper-%d.json", k.Index()))
		if err := keypernet.SaveKeyper(path, k); err != nil {
			fatalf("save key file: %v", err)
		}
		fmt.Printf("wrote %s\n", path)
	}
	export, err := keypernet.ExportCommittee(*t, mpk, registryAddr, keyperAddrs)
	if err != nil {
		fatalf("export committee: %v", err)
	}
	blob, _ := json.MarshalIndent(export, "", "  ")
	committeePath := filepath.Join(*dir, "committee.json")
	if err := os.WriteFile(committeePath, blob, 0o644); err != nil {
		fatalf("write committee: %v", err)
	}
	fmt.Printf("wrote %s\n", committeePath)
	fmt.Println("DEVNET ONLY: this operator holds the entire committee; this provides no threshold trust.")
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	keyPath := fs.String("key", "", "keyper key file (from bootstrap)")
	addr := fs.String("addr", "127.0.0.1:9700", "HTTP listen address")
	auth := fs.String("auth", "", "shared-secret token required from requesters (empty = open; not recommended)")
	disabled := fs.Bool("disabled", false, "start with share release disabled (trigger off)")
	trigger := fs.Uint64("trigger", 0, "initial highest epoch for which to release keys")
	chainhead := fs.String("chainhead", "", "JSON-RPC URL of a node to follow; advances the release trigger to the chain head so future-epoch keys are never released")
	poll := fs.Duration("poll", 2*time.Second, "chain-head poll interval")
	fs.Parse(args)

	if *keyPath == "" {
		fatalf("-key is required")
	}
	k, err := keypernet.LoadKeyper(*keyPath)
	if err != nil {
		fatalf("load key: %v", err)
	}
	server := keypernet.NewServer(k, *auth)
	server.SetTriggerEpoch(*trigger)
	server.SetEnabled(!*disabled)

	// Follow the chain head: a keyper must only release an epoch's key once that
	// epoch is due, so the release trigger tracks the current block number. Without
	// this, -trigger is a static bound the operator advances manually.
	if *chainhead != "" {
		go followChainHead(*chainhead, *poll, server)
	} else {
		fmt.Fprintln(os.Stderr, "WARNING: no -chainhead; the release trigger is static and must be advanced manually")
	}

	if *auth == "" {
		fmt.Fprintln(os.Stderr, "WARNING: serving with no auth token; any party can request decryption shares")
	}
	fmt.Printf("keyper %d serving on %s%s (enabled=%v)\n", k.Index(), *addr, keypernet.EpochSharePath, !*disabled)
	if err := http.ListenAndServe(*addr, server.Handler()); err != nil {
		fatalf("serve: %v", err)
	}
}

// followChainHead polls a node's eth_blockNumber and advances the keyper's release
// trigger to the head block number, so the keyper only releases keys for epochs at
// or below the current chain height.
func followChainHead(url string, interval time.Duration, server *keypernet.Server) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var last uint64
	for range ticker.C {
		head, err := blockNumber(url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "keyper: chain-head poll failed: %v\n", err)
			continue
		}
		if head != last {
			server.SetTriggerEpoch(head)
			last = head
		}
	}
}

// blockNumber queries eth_blockNumber over JSON-RPC.
func blockNumber(url string) (uint64, error) {
	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`)
	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var out struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	if out.Error != nil {
		return 0, fmt.Errorf("rpc error: %s", out.Error.Message)
	}
	return strconv.ParseUint(strings.TrimPrefix(out.Result, "0x"), 16, 64)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "keyper: "+format+"\n", args...)
	os.Exit(1)
}
