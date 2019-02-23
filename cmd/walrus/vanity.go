package main

import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/wallet"
)

func vanity(seed wallet.Seed, substr string) {
	for _, c := range substr {
		if !strings.ContainsRune("0123456789abcdef", c) {
			log.Fatal(`Invalid substring: addresses can only contain the characters "0123456789abcdef"`)
		}
	}
	wantPrefix := true
	var addrsReq50, addrsReq97 uint64
	var matchLen func(addr types.UnlockHash, bestLen int) int
	if wantPrefix {
		addrsReq50 = uint64(1) << uint64(len(substr)*4)
		addrsReq97 = addrsReq50 << 4
		matchLen = func(addr types.UnlockHash, bestLen int) int {
			n := bestLen
			addrStr := addr.String()
			if !strings.HasPrefix(addrStr, substr[:n]) {
				return 0
			}
			for n < len(substr) && strings.HasPrefix(addrStr, substr[:n+1]) {
				n++
			}
			return n
		}
	} else {
		addrsReq50 = (uint64(1) << uint64(len(substr)*4)) / uint64(64-len(substr))
		addrsReq97 = addrsReq50 << 4
		matchLen = func(addr types.UnlockHash, bestLen int) int {
			n := bestLen
			addrStr := addr.String()
			if !strings.Contains(addrStr, substr[:n]) {
				return 0
			}
			for n < len(substr) && strings.Contains(addrStr, substr[:n+1]) {
				n++
			}
			return n
		}
	}

	var total uint64
	numCPU := runtime.NumCPU()
	resChan := make(chan uint64, numCPU)
	for cpu := 0; cpu < numCPU; cpu++ {
		go func(offset uint64) {
			seed := seed
			bestLen := 1
			for i := offset; ; i += uint64(numCPU) {
				if n := matchLen(wallet.StandardAddress(seed.PublicKey(i)), bestLen); n > bestLen {
					bestLen = n
					resChan <- i
				}
				atomic.AddUint64(&total, 1)
			}
		}(uint64(cpu))
	}

	var printed bool
	var bestLen int
	var bestIndex uint64
	start := time.Now()
	for {
		select {
		case index := <-resChan:
			if n := matchLen(wallet.StandardAddress(seed.PublicKey(index)), bestLen); n > bestLen {
				bestIndex = index
				bestLen = n
			}
		case <-time.After(time.Second):
			dur := time.Since(start)
			if !printed {
				fmt.Println("\n|                                  Best Match                                  |  Seed Index  |     Speed     |  ETA (50%)  |  ETA (97%)  |")
				printed = true
			}

			bestAddr := wallet.StandardAddress(seed.PublicKey(bestIndex)).String()
			highlight := substr[:bestLen]
			i := strings.Index(bestAddr, highlight)
			bestAddr = bestAddr[:i] + color.RedString(highlight) + bestAddr[i+len(highlight):]
			total := atomic.LoadUint64(&total)
			perSec := uint64(float64(total) / dur.Seconds())
			eta50 := time.Duration((addrsReq50-total)/perSec) * time.Second
			if total > addrsReq50 {
				eta50 = 0
			}
			eta99 := time.Duration((addrsReq97-total)/perSec) * time.Second
			if total > addrsReq97 {
				eta99 = 0
			}
			fmt.Printf("\r| %v |  %9v   | %8v/sec  | %10v  | %10v  |", bestAddr, bestIndex, perSec, eta50, eta99)

			if bestLen == len(substr) {
				if total > addrsReq50 {
					pct := 100.0 * float64(total-addrsReq50) / float64(addrsReq50)
					fmt.Printf("\n\nFound address after %v tries (%v%% more than expected -- bad luck!)\n", total, int(pct))
				} else {
					pct := 100.0 * float64(addrsReq50-total) / float64(addrsReq50)
					fmt.Printf("\n\nFound address after %v tries (%v%% fewer than expected -- good luck!)\n", total, int(pct))
				}
				return
			}
		}
	}
}
