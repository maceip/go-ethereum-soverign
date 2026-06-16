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

	keypers, eon, _, err := keypernet.Bootstrap(*t, *n, rand.Reader)
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
	export, err := keypernet.ExportCommittee(*t, eon, registryAddr, keyperAddrs)
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
	fs.Parse(args)

	if *keyPath == "" {
		fatalf("-key is required")
	}
	k, err := keypernet.LoadKeyper(*keyPath)
	if err != nil {
		fatalf("load key: %v", err)
	}
	server := keypernet.NewServer(k, *auth)
	server.SetEnabled(!*disabled)

	if *auth == "" {
		fmt.Fprintln(os.Stderr, "WARNING: serving with no auth token; any party can request decryption shares")
	}
	fmt.Printf("keyper %d serving on %s%s (enabled=%v)\n", k.Index(), *addr, keypernet.SharePath, !*disabled)
	if err := http.ListenAndServe(*addr, server.Handler()); err != nil {
		fatalf("serve: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "keyper: "+format+"\n", args...)
	os.Exit(1)
}
