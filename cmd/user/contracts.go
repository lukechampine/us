package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"

	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renter/renterutil"
)

func contractinfo(contract proto.ContractRevision) {
	c := makeClient()
	var remaining string
	if height, err := c.ChainHeight(); err == nil {
		if height <= contract.EndHeight() {
			remaining = fmt.Sprintf("(%v blocks remaining)", contract.EndHeight()-height)
		} else {
			remaining = fmt.Sprintf("(expired %v blocks ago)", height-contract.EndHeight())
		}
	}

	fmt.Printf(`Host Key:    %v
Contract ID: %v

End Height:   %v %v
Renter Funds: %v remaining
`, contract.HostKey().Key(), contract.ID(), contract.EndHeight(),
		remaining, currencyUnits(contract.RenterFunds()))
}

func contractName(contract proto.ContractRevision) string {
	id := contract.ID().String()
	return fmt.Sprintf("%s-%s.contract", contract.HostKey().ShortKey(), id[:8])
}

func form(hostKeyPrefix string, funds types.Currency, end string, filename string) error {
	c := makeClient()

	// check that we can create the contract file
	if err := checkCreate(filename); err != nil {
		return err
	}
	hosts, err := c.Hosts()
	if err != nil {
		return errors.Wrap(err, "could not lookup host")
	}
	hostKey, err := lookupHost(hostKeyPrefix, hosts)
	if err != nil {
		return errors.Wrap(err, "could not lookup host")
	}
	host, err := c.Scan(hostKey)
	if err != nil {
		return errors.Wrap(err, "could not scan host")
	}

	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}

	// parse end string
	if end == "" {
		return errors.New("invalid end height or duration")
	}
	var endHeight types.BlockHeight
	switch end[0] {
	case '@':
		intHeight, err := strconv.Atoi(end[1:])
		if err != nil {
			return errors.Wrap(err, "invalid end height")
		}
		endHeight = types.BlockHeight(intHeight)
	default:
		intDuration, err := strconv.Atoi(end)
		if err != nil {
			return errors.Wrap(err, "invalid duration")
		}
		endHeight = currentHeight + types.BlockHeight(intDuration)
	}

	contract, err := proto.FormContract(c, c, host, funds, currentHeight, endHeight)
	if err != nil {
		return err
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

func renew(contractPath string, funds types.Currency, end string, filename string) error {
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
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}

	// parse end string
	if end == "" {
		return errors.New("invalid end height or duration")
	}
	var endHeight types.BlockHeight
	switch end[0] {
	case '@':
		intHeight, err := strconv.Atoi(end[1:])
		if err != nil {
			return errors.Wrap(err, "invalid end height")
		}
		endHeight = types.BlockHeight(intHeight)
	case '+':
		extendDuration, err := strconv.Atoi(end[1:])
		if err != nil {
			return errors.Wrap(err, "invalid extension duration")
		}
		endHeight = uc.ContractRevision.EndHeight() + types.BlockHeight(extendDuration)
	default:
		intDuration, err := strconv.Atoi(end)
		if err != nil {
			return errors.Wrap(err, "invalid duration")
		}
		endHeight = currentHeight + types.BlockHeight(intDuration)
	}

	newContract, err := proto.RenewContract(c, c, uc, host, funds, currentHeight, endHeight)
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
	r := renterutil.CheckupContract(contract, c)
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

func tattle(contractPath string) error {
	contract, err := renter.LoadContract(contractPath)
	if err != nil {
		return errors.Wrap(err, "could not load contract")
	}
	defer contract.Close()

	c := makeClient()
	err = proto.SubmitContractRevision(contract.Revision(), c, c)
	if err != nil {
		return err
	}
	validOutputs := contract.Revision().Revision.NewValidProofOutputs
	missedOutputs := contract.Revision().Revision.NewMissedProofOutputs
	fmt.Printf(`Tattled on %v.

If no more revisions are submitted and the host submits a valid storage
proof, the host will receive %v and %v will be returned to the renter.

If the host does not submit a valid storage proof, the host will receive %v,
%v will be returned to the renter, and %v will be destroyed.
`, contract.HostKey().ShortKey(), currencyUnits(validOutputs[1].Value), currencyUnits(validOutputs[0].Value),
		currencyUnits(missedOutputs[1].Value), currencyUnits(missedOutputs[0].Value), currencyUnits(missedOutputs[2].Value))
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
