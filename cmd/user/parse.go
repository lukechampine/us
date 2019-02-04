package main

import (
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gitlab.com/NebulousLabs/Sia/types"
)

// assume metafiles have this extension
const metafileExt = ".usa"

// detect whether the user is redirecting stdin or stdout
// (not perfect; doesn't work with e.g. /dev/zero)
func isCharDevice(f *os.File) bool {
	stat, _ := f.Stat()
	return (stat.Mode() & os.ModeCharDevice) != 0
}

var redirStdout = !isCharDevice(os.Stdout)

// form [hostkey] [funds] [endheight/duration]
// form [hostkey] [funds] [endheight/duration] [contract]
func parseForm(args []string, cmd *flag.FlagSet) (string, types.Currency, string, string) {
	if len(args) == 3 {
		args = append(args, "") // contract filename is optional
	}
	if len(args) != 4 {
		cmd.Usage()
		os.Exit(2)
	}
	return args[0], scanCurrency(args[1]), args[2], args[3]
}

// renew [contract] [funds] [endheight/duration]
// renew [contract] [funds] [endheight/duration] [newcontract]
func parseRenew(args []string, cmd *flag.FlagSet) (string, types.Currency, string, string) {
	if len(args) == 3 {
		args = append(args, "") // contract filename is optional
	}
	if len(args) != 4 {
		cmd.Usage()
		os.Exit(2)
	}
	return args[0], scanCurrency(args[1]), args[2], args[3]
}

// scan [hostkey] [bytes] [duration] [downloads]
func parseScan(args []string, cmd *flag.FlagSet) (string, uint64, types.BlockHeight, float64) {
	if len(args) != 4 {
		cmd.Usage()
		os.Exit(2)
	}
	return args[0], scanFilesize(args[1]), scanBlockHeight(args[2]), scanFloat(args[3])
}

// upload [file]
// upload [file] [metafile]
func parseUpload(args []string, cmd *flag.FlagSet) (file *os.File, metaPath string) {
	if !(len(args) == 1 || len(args) == 2) {
		cmd.Usage()
		os.Exit(2)
	}
	if len(args) == 1 {
		args = append(args, ".")
	}
	f, err := os.Open(args[0])
	check("Could not open file:", err)
	stat0, err := f.Stat()
	check("Could not stat file:", err)
	stat1, err := os.Stat(args[1])
	if err == nil && stat1.IsDir() && !stat0.IsDir() {
		// if [metafile] is a folder, and [file] is not a folder, assume that
		// the user wants to create a metafile named [metafile]/[file].usa
		args[1] = filepath.Join(args[1], filepath.Base(args[0])+metafileExt)
	}
	return f, args[1]
}

// download [metafile]
// download [metafile] [file]
// download [metafolder] [folder]
func parseDownload(args []string, cmd *flag.FlagSet) (file *os.File, metaPath string) {
	if !(len(args) == 1 || len(args) == 2) {
		cmd.Usage()
		os.Exit(2)
	}
	metaPath = args[0]
	if len(args) == 1 {
		if redirStdout {
			return os.Stdout, args[0]
		}
		args = append(args, ".")
	}
	isDir := func(path string) bool {
		stat, err := os.Stat(path)
		return err == nil && stat.IsDir()
	}
	var err error
	srcIsDir, dstIsDir := isDir(metaPath), isDir(args[1])
	switch {
	case srcIsDir && dstIsDir:
		file, err = os.Open(args[1])
		check("Could not open destination folder:", err)
	case srcIsDir && !dstIsDir:
		cmd.Usage()
		os.Exit(2)
	case !srcIsDir && dstIsDir:
		metabase := filepath.Base(args[0])
		if !strings.HasSuffix(metabase, metafileExt) {
			log.Fatalf("Could not infer download destination: metafile path does not end in %v", metafileExt)
		}
		args[1] = filepath.Join(args[1], strings.TrimSuffix(metabase, metafileExt))
		fallthrough
	case !srcIsDir && !dstIsDir:
		file, err = os.OpenFile(args[1], os.O_CREATE|os.O_RDWR, 0666)
		check("Could not create file:", err)
	}
	return file, metaPath
}

// checkup [metafile]
// checkup [contract]
func parseCheckup(args []string, cmd *flag.FlagSet) (metaPath string) {
	if len(args) != 1 {
		cmd.Usage()
		os.Exit(2)
	}
	return args[0]
}

func scanCurrency(s string) types.Currency {
	var hastings string
	if strings.HasSuffix(s, "H") {
		hastings = strings.TrimSuffix(s, "H")
	} else {
		units := []string{"pS", "nS", "uS", "mS", "SC", "KS", "MS", "GS", "TS"}
		for i, unit := range units {
			if strings.HasSuffix(s, unit) {
				// scan into big.Rat
				r, ok := new(big.Rat).SetString(strings.TrimSuffix(s, unit))
				if !ok {
					log.Fatal("Malformed currency value")
				}
				// convert units
				exp := 24 + 3*(int64(i)-4)
				mag := new(big.Int).Exp(big.NewInt(10), big.NewInt(exp), nil)
				r.Mul(r, new(big.Rat).SetInt(mag))
				// r must be an integer at this point
				if !r.IsInt() {
					log.Fatal("Non-integer number of hastings")
				}
				hastings = r.RatString()
				break
			}
		}
	}
	if hastings == "" {
		log.Fatal("Currency value is missing units")
	}
	var c types.Currency
	_, err := fmt.Sscan(hastings, &c)
	check("Could not scan currency value:", err)
	return c
}

func scanBlockHeight(s string) types.BlockHeight {
	height, err := strconv.Atoi(s)
	check("Malformed blockheight:", err)
	return types.BlockHeight(height)
}

func scanFilesize(s string) (bytes uint64) {
	units := []struct {
		suffix     string
		multiplier uint64
	}{
		{"kb", 1e3},
		{"mb", 1e6},
		{"gb", 1e9},
		{"tb", 1e12},
		{"kib", 1 << 10},
		{"mib", 1 << 20},
		{"gib", 1 << 30},
		{"tib", 1 << 40},
		{"b", 1},
	}

	s = strings.ToLower(s)
	for _, unit := range units {
		if strings.HasSuffix(s, unit.suffix) {
			_, err := fmt.Sscan(s, &bytes)
			check("Malformed filesize:", err)
			bytes *= unit.multiplier
			return
		}
	}

	// no units
	_, err := fmt.Sscan(s, &bytes)
	check("Malformed filesize:", err)
	return
}

func scanFloat(s string) (f float64) {
	_, err := fmt.Sscan(s, &f)
	check("Malformed number:", err)
	return
}
