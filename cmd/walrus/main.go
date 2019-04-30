package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"gitlab.com/NebulousLabs/Sia/build"
	"gitlab.com/NebulousLabs/Sia/modules/consensus"
	"gitlab.com/NebulousLabs/Sia/modules/gateway"
	"gitlab.com/NebulousLabs/Sia/modules/transactionpool"
	"golang.org/x/crypto/ssh/terminal"
	"lukechampine.com/flagg"
	"lukechampine.com/us/wallet"
)

var (
	// to be supplied at build time
	githash   = "?"
	builddate = "?"
)

var (
	rootUsage = `Usage:
    walrus [flags] [action]

Actions:
    seed            generate a random seed
    start           start the wallet and API server
    gen             derive an address from a key index
    vanity          generate a vanity address
`
	versionUsage = rootUsage

	seedUsage = `Usage:
    walrus seed

Generate a random seed. For security, considering bypassing the terminal by
immediately storing the seed in an environment variable, like so:

    export WALRUS_SEED=$(walrus seed)

Other commands will use this environment variable automatically.
`

	startUsage = `Usage:
    walrus start

Start the wallet and begin serving the HTTP API. If the WALRUS_SEED environment
variable is set, that seed phrase will be used; otherwise, you will be
prompted for your seed phrase.
`

	resetUsage = `Usage:
    walrus reset

Resets the wallet's knowledge of the blockchain. All transactions and UTXOs
will be forgotten, and the next time the wallet starts, it will begin scanning
from the genesis block. This takes a long time! Resetting is typically only
necessary if you have added addresses to a watch-only wallet that have already
been seen on the blockchain.
`

	genUsage = `Usage:
    walrus gen keyindex

Derive an address from the specified key index. If the WALRUS_SEED environment
variable is set, that seed phrase will be used; otherwise, you will be
prompted for your seed phrase.
`

	vanityUsage = `Usage:
    walrus vanity substr

Generate an address containing the desired substring.
`
)

var usage = flagg.SimpleUsage(flagg.Root, rootUsage)

func getSeed() wallet.Seed {
	phrase := os.Getenv("WALRUS_SEED")
	if phrase != "" {
		fmt.Println("Using WALRUS_SEED environment variable")
	} else {
		fmt.Print("Seed: ")
		pw, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatal("Could not read seed phrase:", err)
		}
		fmt.Println()
		phrase = string(pw)
	}
	seed, err := wallet.SeedFromPhrase(phrase)
	if err != nil {
		log.Fatal(err)
	}
	return seed
}

func main() {
	log.SetFlags(0)

	rootCmd := flagg.Root
	rootCmd.Usage = flagg.SimpleUsage(rootCmd, rootUsage)
	versionCmd := flagg.New("version", versionUsage)
	seedCmd := flagg.New("seed", seedUsage)
	startCmd := flagg.New("start", startUsage)
	watch := startCmd.Bool("watch-only", false, "run in watch-only mode")
	addr := startCmd.String("http", ":9380", "host:port to serve on")
	dir := startCmd.String("dir", ".", "directory to store in")
	resetCmd := flagg.New("reset", resetUsage)
	resetDir := resetCmd.String("dir", ".", "directory where wallet is stored")
	genCmd := flagg.New("gen", genUsage)
	vanityCmd := flagg.New("vanity", vanityUsage)

	cmd := flagg.Parse(flagg.Tree{
		Cmd: rootCmd,
		Sub: []flagg.Tree{
			{Cmd: versionCmd},
			{Cmd: seedCmd},
			{Cmd: startCmd},
			{Cmd: resetCmd},
			{Cmd: genCmd},
			{Cmd: vanityCmd},
		},
	})
	args := cmd.Args()

	switch cmd {
	case rootCmd, versionCmd:
		if len(args) > 0 {
			usage()
			return
		}
		log.Printf("walrus v0.1.0\nCommit:     %s\nRelease:    %s\nGo version: %s %s/%s\nBuild Date: %s\n",
			githash, build.Release, runtime.Version(), runtime.GOOS, runtime.GOARCH, builddate)

	case seedCmd:
		if len(args) != 0 {
			seedCmd.Usage()
		}
		fmt.Println(wallet.NewSeed())

	case startCmd:
		if len(args) != 0 {
			startCmd.Usage()
			return
		}
		if *watch {
			if err := startWatchOnly(*dir, *addr); err != nil {
				log.Fatal(err)
			}
		} else {
			if err := start(getSeed(), *dir, *addr); err != nil {
				log.Fatal(err)
			}
		}

	case resetCmd:
		if len(args) != 0 {
			resetCmd.Usage()
			return
		}
		if err := reset(*resetDir); err != nil {
			log.Fatal(err)
		}

	case genCmd:
		if len(args) != 1 {
			genCmd.Usage()
			return
		}
		if err := gen(getSeed(), args[0]); err != nil {
			log.Fatalln("Could not generate address:", err)
		}

	case vanityCmd:
		if len(args) != 1 {
			vanityCmd.Usage()
			return
		}
		vanity(getSeed(), args[0])
	}
}

func start(seed wallet.Seed, dir string, APIaddr string) error {
	g, err := gateway.New(":9381", true, filepath.Join(dir, "gateway"))
	if err != nil {
		return err
	}
	cs, err := consensus.New(g, true, filepath.Join(dir, "consensus"))
	if err != nil {
		return err
	}
	tp, err := transactionpool.New(cs, g, filepath.Join(dir, "tpool"))
	if err != nil {
		return err
	}

	store, err := wallet.NewBoltDBStore(filepath.Join(dir, "wallet.db"), nil)
	if err != nil {
		return err
	}
	sm := wallet.NewSeedManager(seed, store.SeedIndex())
	w := wallet.NewSeedWallet(sm, store)
	err = cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)
	if err != nil {
		return err
	}
	ss := NewSeedServer(w, tp)

	log.Printf("Listening on %v...", APIaddr)
	return http.ListenAndServe(APIaddr, ss)
}

func startWatchOnly(dir string, APIaddr string) error {
	g, err := gateway.New(":9381", true, filepath.Join(dir, "gateway"))
	if err != nil {
		return err
	}
	cs, err := consensus.New(g, true, filepath.Join(dir, "consensus"))
	if err != nil {
		return err
	}
	tp, err := transactionpool.New(cs, g, filepath.Join(dir, "tpool"))
	if err != nil {
		return err
	}

	store, err := wallet.NewBoltDBStore(filepath.Join(dir, "wallet.db"), nil)
	if err != nil {
		return err
	}
	w := wallet.NewWatchOnlyWallet(store)
	err = cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)
	if err != nil {
		return err
	}
	ss := NewWatchSeedServer(w, tp)

	log.Printf("Listening on %v...", APIaddr)
	return http.ListenAndServe(APIaddr, ss)
}

func reset(dir string) error {
	store, err := wallet.NewBoltDBStore(filepath.Join(dir, "wallet.db"), nil)
	if err != nil {
		return err
	}
	return store.Reset()
}
