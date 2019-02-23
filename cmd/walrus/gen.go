package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/pkg/errors"
	"lukechampine.com/us/wallet"
)

func gen(indexStr string) error {
	index, err := strconv.ParseUint(indexStr, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid key index")
	}
	phrase := os.Getenv("WALRUS_SEED")
	if phrase == "" {
		fmt.Print("Seed: ")
		pw, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return errors.Wrap(err, "could not read seed phrase")
		}
		fmt.Println()
		phrase = string(pw)
	}
	seed, err := wallet.SeedFromPhrase(phrase)
	if err != nil {
		return err
	}
	uc := wallet.StandardUnlockConditions(seed.PublicKey(index))
	euc := *(*encodedUnlockConditions)(unsafe.Pointer(&uc))
	js, _ := json.MarshalIndent(struct {
		UnlockConditions encodedUnlockConditions `json:"unlockConditions"`
		KeyIndex         uint64                  `json:"keyIndex"`
	}{euc, index}, "", "\t")
	fmt.Println(uc.UnlockHash())
	fmt.Println(string(js))
	return nil
}