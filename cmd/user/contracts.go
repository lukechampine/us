package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/internal/ed25519"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renter/renterutil"
	"lukechampine.com/us/renterhost"
)

const contractExt = ".contract"

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
Sectors:      %v (%v)
`, contract.HostKey().Key(), contract.ID(), contract.EndHeight(),
		remaining, currencyUnits(contract.RenterFunds()),
		contract.Revision.NewFileSize/renterhost.SectorSize, filesizeUnits(int64(contract.Revision.NewFileSize)))
}

func listcontracts() error {
	os.MkdirAll(config.ContractsAvailable, 0700)
	os.MkdirAll(config.ContractsEnabled, 0700)
	// first build set of enabled contracts
	d, err := os.Open(config.ContractsEnabled)
	if err != nil {
		return errors.Wrap(err, "could not open enabled contract dir")
	}
	defer d.Close()
	filenames, err := d.Readdirnames(-1)
	if err != nil {
		return errors.Wrap(err, "could not read enabled contract dir")
	}
	enabled := make(map[string]struct{})
	for _, name := range filenames {
		if filepath.Ext(name) != contractExt {
			continue
		}
		enabled[name] = struct{}{}
	}
	d.Close()

	// then read available contracts
	d, err = os.Open(config.ContractsAvailable)
	if err != nil {
		return errors.Wrap(err, "could not open available contract dir")
	}
	defer d.Close()
	filenames, err = d.Readdirnames(-1)
	if err != nil {
		return errors.Wrap(err, "could not read available contract dir")
	}
	type entry struct {
		host      hostdb.HostPublicKey
		id        types.FileContractID
		enabled   bool
		endHeight types.BlockHeight
		funds     types.Currency
	}
	var entries []entry
	for _, name := range filenames {
		if filepath.Ext(name) != contractExt {
			// skip archived contracts and other files
			continue
		}
		rev, err := renter.ReadContractRevision(filepath.Join(config.ContractsAvailable, name))
		if err != nil {
			return errors.Wrap(err, "could not read contract")
		}
		_, ok := enabled[name]
		entries = append(entries, entry{
			host:      rev.HostKey(),
			id:        rev.ID(),
			enabled:   ok,
			endHeight: rev.EndHeight(),
			funds:     rev.RenterFunds(),
		})
	}
	// sort by Enabled, then alphabetically by host
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].enabled != entries[j].enabled {
			return entries[i].enabled
		}
		return entries[i].host.Key() < entries[j].host.Key()
	})

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 4, ' ', 0)
	fmt.Fprintf(tw, "Host\tContract\tEnabled\tEnd Height\tFunds Remaining\n")
	for _, e := range entries {
		id := hex.EncodeToString(e.id[:4])
		en := " "
		if e.enabled {
			en = "*"
		}
		fmt.Fprintf(tw, "%v\t%v\t%v\t%v\t%v\n", e.host.ShortKey(), id, en, e.endHeight, currencyUnits(e.funds))
	}
	return tw.Flush()
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

	// generate our contract key and execute the protocol
	key := ed25519.NewKeyFromSeed(fastrand.Bytes(32))
	contract, err := proto.FormContract(c, c, key, host, funds, currentHeight, endHeight)
	if err != nil {
		return err
	}

	if filename == "" {
		filename = contractName(contract)
	}
	allPath := filepath.Join(config.ContractsAvailable, filename)
	activePath := filepath.Join(config.ContractsEnabled, filename)
	err = renter.SaveContract(contract, key, allPath)
	if err != nil {
		return errors.Wrap(err, "could not save contract")
	}
	fmt.Println("Wrote contract to", allPath)

	// create symlink in active contracts
	err = os.Symlink(allPath, activePath)
	if err != nil {
		fmt.Println("WARNING: could not enable contract:", err)
		fmt.Printf("To enable this contract, you must run 'user contracts enable %v'\nor create a symlink in %v manually.\n", hostKey.ShortKey(), config.ContractsEnabled)
	} else {
		fmt.Println("Enabled contract by creating", activePath)
		fmt.Printf("To disable this contract, run 'user contracts disable %v'\nor delete the symlink in %v manually.\n", hostKey.ShortKey(), config.ContractsEnabled)
	}

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
		filename = filepath.Join(config.ContractsAvailable, contractName(newContract))
	}
	allPath := filepath.Join(config.ContractsAvailable, filename)
	activePath := filepath.Join(config.ContractsEnabled, filename)
	err = renter.SaveRenewedContract(uc, newContract, filename)
	if err != nil {
		return errors.Wrap(err, "could not save renewed contract")
	}
	fmt.Println("Wrote contract to", allPath)

	// if old contract is in active contract set, remove it
	uc.Close()
	oldActivePath := filepath.Join(config.ContractsEnabled, filepath.Base(contractPath))
	stat, err := os.Stat(oldActivePath)
	if err != nil && !os.IsNotExist(err) {
		fmt.Println("WARNING: could not stat", oldActivePath)
	} else if err == nil {
		if stat.Mode()&os.ModeSymlink == 0 {
			fmt.Printf("WARNING: can't disable old contract (%v) because it is not a symlink.\n", oldActivePath)
			fmt.Println("To disable the old contract, move it to a different folder.")
		} else if err := os.Remove(oldActivePath); err != nil {
			fmt.Printf("WARNING: could not remove %v: %v\n", oldActivePath, err)
		} else {
			fmt.Printf("Removed old contract (%v) from active contracts set.\n", filepath.Base(contractPath))
		}
	}

	// create symlink in active contracts
	err = os.Symlink(allPath, activePath)
	if err != nil {
		fmt.Println("WARNING: could not enable contract:", err)
		fmt.Printf("To enable this contract, you must run 'user contracts enable %v'\nor create a symlink in %v manually.\n", host.PublicKey.ShortKey(), config.ContractsEnabled)
	} else {
		fmt.Println("Enabled contract by creating", activePath)
		fmt.Printf("To disable this contract, run 'user contracts disable %v'\nor delete the symlink in %v manually.\n", host.PublicKey.ShortKey(), config.ContractsEnabled)
	}

	// archive the old contract
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

	c := makeLimitedClient()
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
		os.MkdirAll(config.ContractsAvailable, 0700)
		os.MkdirAll(config.ContractsEnabled, 0700)
		filename = filepath.Join(config.ContractsAvailable, "_test.contract")
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

func enableContract(hostKey string) error {
	os.MkdirAll(config.ContractsAvailable, 0700)
	os.MkdirAll(config.ContractsEnabled, 0700)
	d, err := os.Open(config.ContractsAvailable)
	if err != nil {
		return errors.Wrap(err, "could not open available contract dir")
	}
	defer d.Close()
	filenames, err := d.Readdirnames(-1)
	if err != nil {
		return errors.Wrap(err, "could not read available contract dir")
	}
	var contractName string
	for _, name := range filenames {
		if filepath.Ext(name) != contractExt {
			// skip archived contracts and other files
			continue
		}
		rev, err := renter.ReadContractRevision(filepath.Join(config.ContractsAvailable, name))
		if err != nil {
			return errors.Wrap(err, "could not read contract")
		}
		if string(rev.HostKey()) == hostKey || strings.HasPrefix(rev.HostKey().Key(), hostKey) {
			if contractName != "" {
				return errors.New("ambiguous pubkey")
			}
			contractName = name
		}
	}
	if contractName == "" {
		return errors.New("no contract with that host found")
	}
	err = os.Symlink(
		filepath.Join(config.ContractsAvailable, contractName),
		filepath.Join(config.ContractsEnabled, contractName),
	)
	if err != nil {
		return err
	}
	fmt.Println("Enabled contract by creating symlink", filepath.Join(config.ContractsEnabled, contractName))
	return nil
}

func disableContract(hostKey string) error {
	os.MkdirAll(config.ContractsAvailable, 0700)
	os.MkdirAll(config.ContractsEnabled, 0700)
	d, err := os.Open(config.ContractsEnabled)
	if err != nil {
		return errors.Wrap(err, "could not open enabled contract dir")
	}
	defer d.Close()
	filenames, err := d.Readdirnames(-1)
	if err != nil {
		return errors.Wrap(err, "could not read enabled contract dir")
	}
	var contractPath string
	for _, name := range filenames {
		rev, err := renter.ReadContractRevision(filepath.Join(config.ContractsEnabled, name))
		if err != nil {
			return errors.Wrap(err, "could not read contract")
		}
		if string(rev.HostKey()) == hostKey || strings.HasPrefix(rev.HostKey().Key(), hostKey) {
			if contractPath != "" {
				return errors.New("ambiguous pubkey")
			}
			contractPath = filepath.Join(config.ContractsEnabled, name)
		}
	}
	if contractPath == "" {
		return errors.New("no contract with that host found")
	}

	stat, err := os.Lstat(contractPath)
	if err != nil {
		return errors.Wrap(err, "could not stat contract file")
	} else if stat.Mode()&os.ModeSymlink == 0 {
		return errors.New("refusing to delete non-symlink contract file")
	}
	err = os.Remove(contractPath)
	if err != nil {
		return err
	}
	fmt.Println("Disabled contract by removing symlink", contractPath)
	return nil
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
	hostContractMapping := make(map[hostdb.HostPublicKey]string)
	for _, name := range filenames {
		if filepath.Ext(name) != contractExt {
			// skip archived contracts and other files
			continue
		}
		contractPath := filepath.Join(dir, name)
		rev, err := renter.ReadContractRevision(contractPath)
		if err != nil {
			return nil, errors.Wrap(err, "could not read contract")
		}
		if _, ok := hostContractMapping[rev.HostKey()]; ok {
			return nil, errors.Errorf("multiple contracts for host %v", rev.HostKey())
		}
		hostContractMapping[rev.HostKey()] = contractPath
	}

	contracts := make(renter.ContractSet)
	for _, h := range m.Hosts {
		contractPath, ok := hostContractMapping[h]
		if !ok {
			return nil, errors.Errorf("no contract for host %v", h)
		}
		c, err := renter.LoadContract(contractPath)
		if err != nil {
			return nil, errors.Wrap(err, "could not read contract")
		}
		contracts[h] = c
	}
	return contracts, nil
}
