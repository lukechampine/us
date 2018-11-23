package main

import (
	"log"
	"net/http"
	"path/filepath"
	"runtime"

	"gitlab.com/NebulousLabs/Sia/build"
	"gitlab.com/NebulousLabs/Sia/modules/consensus"
	"gitlab.com/NebulousLabs/Sia/modules/gateway"
	"gitlab.com/NebulousLabs/Sia/modules/transactionpool"
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
    start           start the wallet and API server
    vanity          generate a vanity address
`
	versionUsage = rootUsage

	startUsage = `Usage:
    walrus start

Start the wallet and begin serving the HTTP API.
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

func main() {
	log.SetFlags(0)

	rootCmd := flagg.Root
	rootCmd.Usage = flagg.SimpleUsage(rootCmd, rootUsage)
	versionCmd := flagg.New("version", versionUsage)
	startCmd := flagg.New("start", startUsage)
	watch := startCmd.Bool("watch-only", false, "run in watch-only mode")
	addr := startCmd.String("http", ":9380", "host:port to serve on")
	dir := startCmd.String("dir", ".", "directory to store in")
	genCmd := flagg.New("gen", genUsage)
	vanityCmd := flagg.New("vanity", vanityUsage)

	cmd := flagg.Parse(flagg.Tree{
		Cmd: rootCmd,
		Sub: []flagg.Tree{
			{Cmd: versionCmd},
			{Cmd: startCmd},
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
			if err := start(wallet.Seed{}, *dir, *addr); err != nil {
				log.Fatal(err)
			}
		}

	case genCmd:
		if len(args) != 1 {
			genCmd.Usage()
			return
		}
		if err := gen(args[0]); err != nil {
			log.Fatalln("Could not generate address:", err)
		}

	case vanityCmd:
		if len(args) != 1 {
			vanityCmd.Usage()
			return
		}
		vanity(args[0])
	}
}

func start(seed wallet.Seed, dir string, APIaddr string) error {
	g, err := gateway.New(":9381", false, filepath.Join(dir, "gateway"))
	if err != nil {
		return err
	}
	cs, err := consensus.New(g, false, filepath.Join(dir, "consensus"))
	if err != nil {
		return err
	}
	tp, err := transactionpool.New(cs, g, filepath.Join(dir, "tpool"))
	if err != nil {
		return err
	}

	store, err := wallet.NewBoltDBStore(filepath.Join(dir, "wallet.db"))
	if err != nil {
		return err
	}
	sm := wallet.NewSeedManager(seed, store.SeedIndex())
	w := wallet.NewSeedWallet(sm, store)
	err = cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)
	if err != nil {
		return err
	}
	ss := wallet.NewSeedServer(w, tp)

	log.Printf("Listening on %v...", APIaddr)
	return http.ListenAndServe(APIaddr, ss)
}

func startWatchOnly(dir string, APIaddr string) error {
	g, err := gateway.New(":9381", false, filepath.Join(dir, "gateway"))
	if err != nil {
		return err
	}
	cs, err := consensus.New(g, false, filepath.Join(dir, "consensus"))
	if err != nil {
		return err
	}
	tp, err := transactionpool.New(cs, g, filepath.Join(dir, "tpool"))
	if err != nil {
		return err
	}

	store, err := wallet.NewBoltDBStore(filepath.Join(dir, "wallet.db"))
	if err != nil {
		return err
	}
	w := wallet.NewWatchOnlyWallet(store)
	err = cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)
	if err != nil {
		return err
	}
	ss := wallet.NewWatchSeedServer(w, tp)

	log.Printf("Listening on %v...", APIaddr)
	return http.ListenAndServe(APIaddr, ss)
}
