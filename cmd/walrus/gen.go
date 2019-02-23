package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/pkg/errors"
	"lukechampine.com/us/wallet"
)

func gen(seed wallet.Seed, indexStr string) error {
	index, err := strconv.ParseUint(indexStr, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid key index")
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
