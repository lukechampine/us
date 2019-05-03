package main

import (
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/build"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/flagg"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/renterutil"
)

var (
	// to be supplied at build time
	githash   = "?"
	builddate = "?"
)

var (
	rootUsage = `Usage:
    user [flags] [action]

Actions:
    scan            scan a host
    form            form a contract
    renew           renew a contract
    upload          upload a file
    download        download a file
    checkup         check the health of a file
    migrate         migrate a file to different hosts
    tattle          submit a contract revision to the blockchain
    info            display info about a contract or file
    recover         try to repair a corrupted metafile
`
	versionUsage = rootUsage
	scanUsage    = `Usage:
    user scan hostkey bytes duration downloads

Scans the specified host and reports various metrics.

bytes is the number of bytes intended to be stored on the host; duration is
the number of blocks that the contract will be active; downloads is the
expected ratio of downloads to uploads, i.e. downloads = 0.5 means the user
expects to download half of the uploaded data.
`
	formUsage = `Usage:
    user form hostkey funds duration [filename]
    user form hostkey funds @endheight [filename]

Forms a contract with the specified host for the specified duration with the
specified amount of funds. To specify an exact end height for the contract,
use @endheight; otherwise, the end height will be the current height plus the
supplied duration. Due to various fees, the total number of coins deducted
from the wallet may be greater than funds. Run 'user scan' on the host to see
a breakdown of these fees.

If filename is provided, the resulting contract file will be written to
filename. Otherwise, it will be written to the default contracts directory.
`
	renewUsage = `Usage:
    user renew contract funds duration [filename]
    user renew contract funds @endheight [filename]
    user renew contract funds +extension [filename]

Renews the specified contract (that is, a .contract file) for the specified
duration and with the specified amount of funds. Like 'user form', an exact
end height can be specified using the @ prefix; additionally, a + prefix will
set the end height equal to the old contract end height plus the supplied
extension. Due to various fees, the total number of coins deducted from the
wallet may be greater than funds. Run 'user scan' on the host to see a
breakdown of these fees.

If filename is provided, the resulting contract file will be written to
filename. Otherwise, it will be written to the default contracts directory.

The old contract file is archived by renaming it to contract_old. In most
cases, these archived contracts can be safely deleted. However, it is prudent
to first verify (with the checkup command) that the new contract is usable.
`
	uploadUsage = `Usage:
    user upload file
    user upload file metafile
    user upload file folder
    user upload folder metafolder

Uploads the specified file or folder, storing its metadata in the specified
metafile or as multiple metafiles within the metafolder. The structure of the
metafolder will mirror that of the folder.

If the first argument is a single file and the second is a folder, the
metafile will be stored within folder, using the filename file.usa. For
example, 'user upload foo.txt bar/' will create the metafile 'bar/foo.txt.usa'.

If the destination is unspecified, it is assumed to be the current directory.
For example, 'user upload foo.txt' will create the metafile 'foo.txt.usa'.
`
	downloadUsage = `Usage:
    user download metafile
    user download metafile file
    user download metafile folder
    user download metafolder folder

Downloads the specified metafile or metafolder, storing file data in the
specified file or as multiple files within the folder. The structure of the
folder will mirror that of the metafolder.

If the first argument is a single metafile and the second is a folder, the
file data will be stored within the folder. This form requires that the
metafile have a .usa extension. The destination filename will be the metafile
without the .usa extension. For example, 'user download foo.txt.usa bar/' will
download to 'bar/foo.txt'.

If the destination is unspecified, it is assumed to be the current directory.
For example, 'user download foo.txt.usa' will download to 'foo.txt'.

However, if the destination file is unspecified and stdout is redirected (e.g.
via a pipe), the downloaded file will be written to stdout. For example,
'user download foo.txt.usa | cat' will display the file in the terminal.
`
	checkupUsage = `Usage:
    user checkup metafile
    user checkup contract

Verifies that a randomly-selected sector of the specified metafile or contract
is retrievable, and reports the resulting metrics for each host. Note that
this operation is not free.
`

	contractsUsage = `Usage:
    user contracts action

Actions:
    list            list contracts
    enable          enable a contract
    disable         disable a contract
`

	contractsListUsage = `Usage:
    user contracts list

Lists available and enabled contracts, along with various metadata.
`

	contractsEnableUsage = `Usage:
    user contracts enable hostkey

Enables the contract with the specified host. The contract must be present in
the available contracts directory.
`

	contractsDisableUsage = `Usage:
    user contracts disable hostkey

Enables the contract with the specified host. The contract must be present in
the available contracts directory.
`

	migrateUsage = `Usage:
    user migrate metafile
    user migrate metafolder

Migrates sector data from the metafile's current set of hosts to a new set.
There are three migration strategies, specified by mutually-exclusive flags.
`
	mFileUsage = `Erasure-encode the original file on disk. This is the fastest and
	cheapest option, but it requires a local copy of the file.`

	mDirectUsage = `Upload sectors downloaded directly from old hosts. This is faster and
	cheaper than -remote, but it requires that the old hosts be online.`

	mRemoteUsage = `Download the file from existing hosts and erasure-encode it. This is
	the slowest and most expensive option, but it doesn't require a local
	copy of the file, and it can be performed even if the "old" hosts are
	offline.`

	tattleUsage = `Usage:
	user tattle contract

Broadcasts the contract transaction in the specified file, recording the
latest revision of the contract in the blockchain. Unless a revision is
broadcast before the contract period ends, it's like the contract never
happened; the renter and host both get their money back. As a result, the
renter has little incentive to broadcast a revision (because revisions always
transfer money from the renter to the host), whereas the host has an
overwhelming incentive to broadcast a revision immediately prior to the end of
the contract (in order to maximize the amount of renter funds they receive).

However, if the host is acting maliciously or provide poor service, the renter
can punish them by submitting a revision. This causes the renter to forfeit
whatever money they've already sent to the host, but it also ensures that the
host will lose whatever collateral they've committed. Since the host spends
more on collateral than the renter does on storage, this is an example of
"cutting off your nose to spite your face." It hurts the renter, but it hurts
the host more.

This is rarely the right thing to do, so think carefully before running this
command. In most cases, it's preferable to not submit anything and hope that
the host doesn't either, so you get your money back. It's also important to
know that the host will only lose their collateral if they don't submit a
valid storage proof. So if you think the host is just refusing to talk to you,
bear in mind that they will likely still be able to submit a storage proof and
thus reclaim their collateral. On the other hand, if you think the host has
gone offline or has lost your data, submitting a revision makes more sense.

Lastly, please be aware that broadcasting a revision will incur a standard
transaction fee.
`
	infoUsage = `Usage:
    user info contract
    user info metafile

Displays information about the specified contract or metafile.
`
	recoverUsage = `Usage:
    user recover metafile

Attempt to recover a metafile after a crash. Use this if you notice a
directory with a _workdir suffix -- this indicates unclean shutdown.
`
	serveUsage = `Usage:
    user serve metafolder

Serve the files in metafolder over HTTP.
`
	mountUsage = `Usage:
    user mount metafolder folder

Mount metafolder as a read-only FUSE filesystem, rooted at folder.
`
	convertUsage = `Usage:
    user convert contract

Converts a v1 contract to v2. If conversion fails, the v1 contract is not
affected.
`
)

var usage = flagg.SimpleUsage(flagg.Root, rootUsage) // point-free style!

func check(ctx string, err error) {
	if err != nil {
		log.Fatalln(ctx, err)
	}
}

func makeClient() *renterutil.SiadClient {
	if config.SiadPassword == "" {
		// attempt to read the standard siad password file
		user, err := user.Current()
		check("Could not locate siad password file:", err)
		pw, err := ioutil.ReadFile(filepath.Join(user.HomeDir, ".sia", "apipassword"))
		check("Could not read siad password file:", err)
		config.SiadPassword = strings.TrimSpace(string(pw))
	}
	return renterutil.NewSiadClient(config.SiadAddr, config.SiadPassword)
}

type limitedClient interface {
	Synced() (bool, error)
	ChainHeight() (types.BlockHeight, error)
	renter.HostKeyResolver
}

func makeLimitedClient() limitedClient {
	if config.SHARDAddr == "" {
		return makeClient()
	}
	return renterutil.NewSHARDClient(config.SHARDAddr)
}

func main() {
	log.SetFlags(0)

	err := loadConfig()
	if err != nil {
		check("Could not load config file:", err)
	}

	rootCmd := flagg.Root
	rootCmd.StringVar(&config.SiadAddr, "a", config.SiadAddr, "host:port that the siad API is running on")
	rootCmd.StringVar(&config.SiadPassword, "p", config.SiadPassword, "password required by siad API")
	rootCmd.StringVar(&config.ContractsEnabled, "c", config.ContractsEnabled, "directory containing active contract set")
	rootCmd.Usage = flagg.SimpleUsage(rootCmd, rootUsage)

	versionCmd := flagg.New("version", versionUsage)
	scanCmd := flagg.New("scan", scanUsage)
	formCmd := flagg.New("form", formUsage)
	renewCmd := flagg.New("renew", renewUsage)
	uploadCmd := flagg.New("upload", uploadUsage)
	uploadCmd.IntVar(&config.MinShards, "m", config.MinShards, "minimum number of shards required to download file")
	downloadCmd := flagg.New("download", downloadUsage)
	checkupCmd := flagg.New("checkup", checkupUsage)
	contractsCmd := flagg.New("contracts", contractsUsage)
	contractsListCmd := flagg.New("list", contractsListUsage)
	contractsEnableCmd := flagg.New("enable", contractsEnableUsage)
	contractsDisableCmd := flagg.New("disable", contractsDisableUsage)
	migrateCmd := flagg.New("migrate", migrateUsage)
	mFile := migrateCmd.String("file", "", mFileUsage)
	mDirect := migrateCmd.Bool("direct", false, mDirectUsage)
	mRemote := migrateCmd.Bool("remote", false, mRemoteUsage)
	tattleCmd := flagg.New("tattle", tattleUsage)
	infoCmd := flagg.New("info", infoUsage)
	recoverCmd := flagg.New("recover", recoverUsage)
	serveCmd := flagg.New("serve", serveUsage)
	sAddr := serveCmd.String("addr", ":8080", "HTTP service address")
	mountCmd := flagg.New("mount", mountUsage)
	convertCmd := flagg.New("convert", convertUsage)

	cmd := flagg.Parse(flagg.Tree{
		Cmd: rootCmd,
		Sub: []flagg.Tree{
			{Cmd: versionCmd},
			{Cmd: scanCmd},
			{Cmd: formCmd},
			{Cmd: renewCmd},
			{Cmd: uploadCmd},
			{Cmd: downloadCmd},
			{Cmd: checkupCmd},
			{Cmd: contractsCmd, Sub: []flagg.Tree{
				{Cmd: contractsListCmd},
				{Cmd: contractsEnableCmd},
				{Cmd: contractsDisableCmd},
			}},
			{Cmd: migrateCmd},
			{Cmd: tattleCmd},
			{Cmd: infoCmd},
			{Cmd: recoverCmd},
			{Cmd: serveCmd},
			{Cmd: mountCmd},
			{Cmd: convertCmd},
		},
	})
	args := cmd.Args()

	switch cmd {
	case rootCmd:
		if len(args) > 0 {
			usage()
			return
		}
		fallthrough
	case versionCmd:
		log.Printf("user v0.3.0\nCommit:     %s\nRelease:    %s\nGo version: %s %s/%s\nBuild Date: %s\n",
			githash, build.Release, runtime.Version(), runtime.GOOS, runtime.GOARCH, builddate)

	case scanCmd:
		hostkey, bytes, duration, downloads := parseScan(args, scanCmd)
		err := scan(hostkey, bytes, duration, downloads)
		check("Scan failed:", err)

	case formCmd:
		host, funds, end, filename := parseForm(args, formCmd)
		err := form(host, funds, end, filename)
		check("Contract formation failed:", err)

	case renewCmd:
		contract, funds, end, filename := parseRenew(args, renewCmd)
		err := renew(contract, funds, end, filename)
		check("Renew failed:", err)

	case uploadCmd:
		if config.MinShards == 0 {
			log.Fatalln(`Upload failed: minimum number of shards not specified.
Define min_shards in your config file or supply the -m flag.`)
		}
		f, meta := parseUpload(args, uploadCmd)
		var err error
		if stat, statErr := f.Stat(); statErr == nil && stat.IsDir() {
			err = uploadmetadir(f.Name(), meta, config.ContractsEnabled, config.MinShards)
		} else if _, statErr := os.Stat(meta); !os.IsNotExist(statErr) {
			err = resumeuploadmetafile(f, config.ContractsEnabled, meta)
		} else {
			err = uploadmetafile(f, config.MinShards, config.ContractsEnabled, meta)
		}
		f.Close()
		check("Upload failed:", err)

	case downloadCmd:
		f, meta := parseDownload(args, downloadCmd)
		var err error
		if stat, statErr := f.Stat(); statErr == nil && stat.IsDir() {
			err = downloadmetadir(f.Name(), config.ContractsEnabled, meta)
		} else if f == os.Stdout {
			err = downloadmetastream(f, config.ContractsEnabled, meta)
			// if the pipe we're writing to breaks, it was probably
			// intentional (e.g. 'head' exiting after reading 10 lines), so
			// suppress the error.
			if pe, ok := errors.Cause(err).(*os.PathError); ok {
				if errno, ok := pe.Err.(syscall.Errno); ok && errno == syscall.EPIPE {
					err = nil
				}
			}
		} else {
			err = downloadmetafile(f, config.ContractsEnabled, meta)
			f.Close()
		}
		check("Download failed:", err)

	case checkupCmd:
		path := parseCheckup(args, checkupCmd)
		var err error
		if _, readErr := renter.ReadMetaIndex(path); readErr == nil {
			err = checkupMeta(config.ContractsEnabled, path)
		} else if _, readErr := renter.ReadContractRevision(path); readErr == nil {
			err = checkupContract(path)
		} else {
			log.Fatalln("Not a valid contract or metafile")
		}
		check("Checkup failed:", err)

	case contractsCmd:
		contractsCmd.Usage()

	case contractsListCmd:
		if len(args) != 0 {
			contractsListCmd.Usage()
			return
		}
		err := listcontracts()
		check("Could not list contracts:", err)

	case contractsEnableCmd:
		if len(args) != 1 {
			contractsEnableCmd.Usage()
			return
		}
		err := enableContract(args[0])
		check("Could not enable contract:", err)

	case contractsDisableCmd:
		if len(args) != 1 {
			contractsDisableCmd.Usage()
			return
		}
		err := disableContract(args[0])
		check("Could not disable contract:", err)

	case migrateCmd:
		if len(args) == 0 {
			migrateCmd.Usage()
			return
		}
		meta := args[0]
		stat, statErr := os.Stat(meta)
		isDir := statErr == nil && stat.IsDir()
		var err error
		switch {
		case *mFile == "" && !*mDirect && !*mRemote:
			log.Fatalln("No migration strategy specified (see user migrate --help).")
		case *mFile != "" && !isDir:
			f, ferr := os.Open(*mFile)
			check("Could not open file:", ferr)
			err = migrateFile(f, config.ContractsEnabled, meta)
			f.Close()
		case *mFile != "" && isDir:
			err = migrateDirFile(*mFile, config.ContractsEnabled, meta)
		case *mDirect && !isDir:
			err = migrateDirect(config.ContractsAvailable, config.ContractsEnabled, meta)
		case *mDirect && isDir:
			err = migrateDirDirect(config.ContractsAvailable, config.ContractsEnabled, meta)
		case *mRemote && !isDir:
			err = migrateRemote(config.ContractsEnabled, meta)
		case *mRemote && isDir:
			err = migrateDirRemote(config.ContractsEnabled, meta)
		default:
			log.Fatalln("Multiple migration strategies specified (see user migrate --help).")
		}
		check("Migration failed:", err)

	case tattleCmd:
		if len(args) != 1 {
			tattleCmd.Usage()
			return
		}
		err := tattle(args[0])
		check("Tattling failed:", err)

	case infoCmd:
		if len(args) != 1 {
			infoCmd.Usage()
			return
		}

		if index, shards, err := renter.ReadMetaFileContents(args[0]); err == nil {
			metainfo(index, shards)
		} else if h, err := renter.ReadContractRevision(args[0]); err == nil {
			contractinfo(h)
		} else {
			log.Fatalln("Not a contract or metafile")
		}

	case recoverCmd:
		if len(args) != 1 {
			recoverCmd.Usage()
			return
		}
		err := recoverMeta(args[0])
		check("Recovery failed:", err)

	case serveCmd:
		if len(args) != 1 {
			serveCmd.Usage()
			return
		}
		err := serve(config.ContractsEnabled, args[0], *sAddr)
		if err != nil {
			log.Fatal(err)
		}

	case mountCmd:
		if len(args) != 2 {
			mountCmd.Usage()
			return
		}
		err := mount(config.ContractsEnabled, args[0], args[1])
		if err != nil {
			log.Fatal(err)
		}

	case convertCmd:
		if len(args) != 1 {
			convertCmd.Usage()
			return
		}
		check("Conversion failed:", renter.ConvertContract(args[0]))
	}
}
