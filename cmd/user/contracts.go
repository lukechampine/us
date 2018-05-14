package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NebulousLabs/Sia/types"
	"github.com/pkg/errors"

	"github.com/lukechampine/us/renter"
	"github.com/lukechampine/us/renter/proto"
	"github.com/lukechampine/us/renter/renterutil"
)

func contractinfo(contract proto.ContractTransaction) {
	c := makeClient()
	height := c.ChainHeight()
	var remaining string
	if height <= contract.EndHeight() {
		remaining = fmt.Sprintf("%v blocks remaining", contract.EndHeight()-height)
	} else {
		remaining = fmt.Sprintf("expired %v blocks ago", height-contract.EndHeight())
	}

	fmt.Printf(`Host Key:    %v
Contract ID: %v

End Height:   %v (%v)
Renter Funds: %v remaining
`, contract.HostKey().Key(), contract.ID(), contract.EndHeight(),
		remaining, currencyUnits(contract.RenterFunds()))
}

func contractName(contract proto.ContractTransaction) string {
	id := contract.ID().String()
	return fmt.Sprintf("%s-%s.contract", contract.HostKey().ShortKey(), id[:8])
}

func form(hostKeyPrefix string, funds types.Currency, endHeight types.BlockHeight, filename string) error {
	c := makeClient()

	// check that we can create the contract file
	if err := checkCreate(filename); err != nil {
		return err
	}

	hostKey, err := lookupHost(hostKeyPrefix, c.Hosts())
	if err != nil {
		return errors.Wrap(err, "could not lookup host")
	}
	host, err := c.Scan(hostKey)
	if err != nil {
		return errors.Wrap(err, "could not scan host")
	}

	contract, err := proto.FormContract(c, c, host, funds, c.ChainHeight(), endHeight)
	if err != nil {
		return errors.Wrap(err, "could not form contract")
	}

	if filename == "" {
		filename = filepath.Join(config.Contracts, contractName(contract))
	}
	err = renter.SaveContract(contract, filename)
	if err != nil {
		return errors.Wrap(err, "could not save contract")
	}
	fmt.Println("Wrote contract to", filename)
	return nil
}

func renew(contractPath string, funds types.Currency, endHeight types.BlockHeight, filename string) error {
	c := makeClient()

	uc, err := renter.LoadContract(contractPath)
	if err != nil {
		return errors.Wrap(err, "could not load contract")
	}

	// check that we can create the contract file
	if err := checkCreate(filename); err != nil {
		return err
	}

	host, err := c.Scan(uc.HostKey())
	if err != nil {
		return errors.Wrap(err, "could not scan host")
	}
	newContract, err := proto.RenewContract(c, c, uc, host, funds, c.ChainHeight(), endHeight)
	if err != nil {
		return errors.Wrap(err, "could not renew contract")
	}

	if filename == "" {
		filename = filepath.Join(config.Contracts, contractName(newContract))
	}
	err = renter.SaveRenewedContract(uc, newContract, filename)
	if err != nil {
		return errors.Wrap(err, "could not renew contract")
	}
	fmt.Println("Wrote contract to", filename)

	// archive old contract
	uc.Close()
	oldContractPath := contractPath + "_old"
	err = os.Rename(contractPath, oldContractPath)
	if err != nil {
		fmt.Println("WARNING: could not archive old contract:", err)
		fmt.Println("You may need to manually archive this contract.")
	} else {
		fmt.Println("Archived old contract as", oldContractPath)
	}
	return nil
}

func checkupContract(contractPath string) error {
	contract, err := renter.LoadContract(contractPath)
	if err != nil {
		return errors.Wrap(err, "could not load contract")
	}
	defer contract.Close()

	c := makeClient()
	r := renterutil.CheckupContract(contract, c.Scan)
	if r.Error != nil {
		fmt.Printf("FAIL Host %v:\n\t%v\n", r.Host.ShortKey(), r.Error)
	} else {
		fmt.Printf("OK   Host %v: Latency %0.3fms, Bandwidth %0.3f Mbps\n",
			r.Host.ShortKey(), r.Latency.Seconds()*1000, r.Bandwidth)
	}

	return nil
}

func checkCreate(filename string) error {
	if filename == "" {
		os.MkdirAll(config.Contracts, 0700)
		filename = filepath.Join(config.Contracts, "_test.contract")
	}
	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "could not create contract file")
	}
	f.Close()
	os.Remove(filename)
	return nil
}

func loadContracts(dir string) (renter.ContractSet, error) {
	contracts, err := renter.LoadContracts(dir)
	if err != nil {
		return nil, err
	} else if len(contracts) == 0 {
		return nil, errors.New("contract set is empty")
	} else if len(config.Hosts) == 0 {
		return contracts, nil
	}

	added := make([]bool, len(config.Hosts))
outer:
	for host, c := range contracts {
		for i, h := range config.Hosts {
			if strings.HasPrefix(host.Key(), h) {
				if added[i] {
					contracts.Close()
					return nil, errors.Errorf("ambiguous pubkey %q", h)
				}
				added[i] = true
				continue outer
			}
		}
		c.Close()
		delete(contracts, host)
	}
	for i, h := range config.Hosts {
		if !added[i] {
			return nil, errors.Errorf("pubkey %q not found in contract set", h)
		}
	}
	return contracts, nil
}

func loadMetaContracts(m *renter.MetaFile, dir string) (renter.ContractSet, error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, errors.Wrap(err, "could not open contract dir")
	}
	defer d.Close()
	filenames, err := d.Readdirnames(-1)
	if err != nil {
		return nil, errors.Wrap(err, "could not read contract dir")
	}

	contracts := make(renter.ContractSet)
	for _, h := range m.Hosts {
		for _, name := range filenames {
			if strings.HasPrefix(name, h.ShortKey()) {
				c, err := renter.LoadContract(filepath.Join(dir, name))
				if err != nil {
					return nil, errors.Wrap(err, "could not read contract")
				}
				contracts[h] = c
			}
		}
	}
	return contracts, nil
}
