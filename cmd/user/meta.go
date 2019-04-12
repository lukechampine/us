package main

import (
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"

	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/renterutil"
	"lukechampine.com/us/renterhost"

	"github.com/pkg/errors"
)

func metainfo(m renter.MetaIndex, shards [][]renter.SectorSlice) {
	var uploaded int64
	for _, shard := range shards {
		for _, s := range shard {
			uploaded += int64(s.NumSegments * merkle.SegmentSize)
		}
	}
	redundantSize := m.Filesize * int64(len(m.Hosts)) / int64(m.MinShards)

	fmt.Printf(`Filesize:   %v
Redundancy: %v-of-%v (%0.2gx replication)
Uploaded:   %v (%0.2f%% of full redundancy)
`, filesizeUnits(m.Filesize), m.MinShards, len(m.Hosts), float64(len(m.Hosts))/float64(m.MinShards),
		filesizeUnits(uploaded), 100*float64(uploaded)/float64(redundantSize))
	fmt.Println("Hosts:")
	for _, hostKey := range m.Hosts {
		fmt.Printf("    %v\n", hostKey)
	}
}

// filesize returns a string that displays a filesize in human-readable units.
func filesizeUnits(size int64) string {
	if size == 0 {
		return "0 B"
	}
	sizes := []string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
	i := int(math.Log10(float64(size)) / 3)
	// printf trick: * means "print to 'i' digits"
	// so we get 1 decimal place for KB, 2 for MB, 3 for GB, etc.
	return fmt.Sprintf("%.*f %s", i, float64(size)/math.Pow10(3*i), sizes[i])
}

func closeMetaFile(m *renter.MetaFile) {
	if err := m.Close(); err != nil {
		log.Println("ERROR: could not create metafile archive:", err)
	}
}

func uploadmetafile(f *os.File, minShards int, contractDir, metaPath string) error {
	contracts, err := renter.LoadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	stat, err := f.Stat()
	if err != nil {
		return errors.Wrap(err, "could not stat file")
	}
	m, err := renter.NewMetaFile(metaPath, stat.Mode(), stat.Size(), contracts, minShards)
	if err != nil {
		return errors.Wrap(err, "could not create metafile")
	}
	defer closeMetaFile(m)

	c := makeLimitedClient()
	if synced, err := c.Synced(); !synced && err == nil {
		return errors.New("blockchain is not synchronized")
	}
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}
	log, cleanup := openLog()
	defer cleanup()
	op := renterutil.Upload(f, contracts, m, c, currentHeight)
	return trackUpload(f.Name(), op, log)
}

func uploadmetadir(dir, metaDir, contractDir string, minShards int) error {
	contracts, err := renter.LoadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	c := makeLimitedClient()
	if synced, err := c.Synced(); !synced && err == nil {
		return errors.New("blockchain is not synchronized")
	}
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}

	log, cleanup := openLog()
	defer cleanup()
	fileIter := renterutil.NewRecursiveFileIter(dir, metaDir)
	op := renterutil.UploadDir(fileIter, contracts, minShards, c, currentHeight)
	return trackUploadDir(op, log)
}

func resumeuploadmetafile(f *os.File, contractDir, metaPath string) error {
	contracts, err := renter.LoadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	m, err := renter.OpenMetaFile(metaPath)
	if err != nil {
		return errors.Wrap(err, "could not load metafile")
	}
	defer closeMetaFile(m)

	c := makeLimitedClient()
	if synced, err := c.Synced(); !synced && err == nil {
		return errors.New("blockchain is not synchronized")
	}
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}
	log, cleanup := openLog()
	defer cleanup()
	op := renterutil.Upload(f, contracts, m, c, currentHeight)
	return trackUpload(f.Name(), op, log)
}

func resumedownload(f *os.File, metaPath string, pf renterutil.PseudoFile) error {
	if ok, err := renter.MetaFileCanDownload(metaPath); err == nil && !ok {
		return errors.New("file is not sufficiently uploaded")
	}
	// set file mode and size
	stat, err := f.Stat()
	if err != nil {
		return errors.Wrap(err, "could not stat file")
	}
	pstat, err := pf.Stat()
	if err != nil {
		return err
	}
	if stat.Mode() != pstat.Mode() {
		if err := f.Chmod(pstat.Mode()); err != nil {
			return errors.Wrap(err, "could not set file mode")
		}
	}
	if stat.Size() > pstat.Size() {
		if err := f.Truncate(pstat.Size()); err != nil {
			return errors.Wrap(err, "could not resize file")
		}
	}

	// TODO: if file is already partially downloaded, pick up where we left off
	return trackCopy(f, pf, 0)
}

func downloadmetafile(f *os.File, contractDir, metaPath string) error {
	if ok, err := renter.MetaFileCanDownload(metaPath); err == nil && !ok {
		return errors.New("file is not sufficiently uploaded")
	}
	contracts, err := renter.LoadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	dir, name := filepath.Dir(metaPath), strings.TrimSuffix(filepath.Base(metaPath), ".usa")
	fs, err := renterutil.NewFileSystem(dir, contracts, makeLimitedClient())
	if err != nil {
		return err
	}
	defer fs.Close()
	pf, err := fs.Open(name)
	if err != nil {
		return err
	}
	defer pf.Close()
	return resumedownload(f, metaPath, pf)
}

func downloadmetastream(w io.Writer, contractDir, metaPath string) error {
	if ok, err := renter.MetaFileCanDownload(metaPath); err == nil && !ok {
		return errors.New("file is not sufficiently uploaded")
	}
	contracts, err := renter.LoadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	dir, name := filepath.Dir(metaPath), strings.TrimSuffix(filepath.Base(metaPath), ".usa")
	fs, err := renterutil.NewFileSystem(dir, contracts, makeLimitedClient())
	if err != nil {
		return err
	}
	defer fs.Close()
	pf, err := fs.Open(name)
	if err != nil {
		return err
	}
	defer pf.Close()
	stat, err := pf.Stat()
	if err != nil {
		return err
	} else if stat.IsDir() {
		return errors.New("is a directory")
	}
	index := stat.Sys().(renter.MetaIndex)

	buf := make([]byte, renterhost.SectorSize*index.MinShards)
	_, err = io.CopyBuffer(w, pf, buf)
	return err
}

func downloadmetadir(dir, contractDir, metaDir string) error {
	contracts, err := renter.LoadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()
	fs, err := renterutil.NewFileSystem(metaDir, contracts, makeLimitedClient())
	if err != nil {
		return err
	}
	defer fs.Close()

	return filepath.Walk(metaDir, func(metaPath string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		name := strings.TrimSuffix(strings.TrimPrefix(metaPath, metaDir), ".usa")
		pf, err := fs.Open(name)
		if err != nil {
			return err
		}
		defer pf.Close()
		fpath := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(fpath), 0700)
		f, err := os.OpenFile(fpath, os.O_RDWR|os.O_CREATE, info.Mode())
		if err != nil {
			return err
		}
		return resumedownload(f, metaPath, pf)
	})
}

func checkupMeta(contractDir, metaPath string) error {
	contracts, err := renter.LoadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	m, err := renter.OpenMetaFile(metaPath)
	if err != nil {
		return errors.Wrap(err, "could not load metafile")
	}
	defer closeMetaFile(m)

	c := makeLimitedClient()
	for r := range renterutil.Checkup(contracts, m, c) {
		if r.Error != nil {
			fmt.Printf("FAIL Host %v:\n\t%v\n", r.Host.ShortKey(), r.Error)
		} else {
			fmt.Printf("OK   Host %v: Latency %0.3fms, Bandwidth %0.3f Mbps\n",
				r.Host.ShortKey(), r.Latency.Seconds()*1000, r.Bandwidth)
		}
	}

	return nil
}

func migrateFile(f *os.File, newContractsDir, metaPath string) error {
	newcontracts, err := renter.LoadContracts(newContractsDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer newcontracts.Close()

	m, err := renter.OpenMetaFile(metaPath)
	if err != nil {
		return errors.Wrap(err, "could not load metafile")
	}
	defer closeMetaFile(m)

	c := makeLimitedClient()
	if synced, err := c.Synced(); !synced && err == nil {
		return errors.New("blockchain is not synchronized")
	}
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}
	op := renterutil.MigrateFile(f, newcontracts, m, c, currentHeight)
	return trackMigrateFile(metaPath, op)
}

func migrateDirFile(dir, newContractsDir, metaDir string) error {
	newcontracts, err := renter.LoadContracts(newContractsDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer newcontracts.Close()

	c := makeLimitedClient()
	if synced, err := c.Synced(); !synced && err == nil {
		return errors.New("blockchain is not synchronized")
	}
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}
	metafileIter := renterutil.NewRecursiveMetaFileIter(metaDir, dir)
	op := renterutil.MigrateDirFile(newcontracts, metafileIter, c, currentHeight)
	return trackMigrateDir(op)
}

func migrateDirect(allContractsDir, newContractsDir, metaPath string) error {
	newcontracts, err := renter.LoadContracts(newContractsDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer newcontracts.Close()

	m, err := renter.OpenMetaFile(metaPath)
	if err != nil {
		return errors.Wrap(err, "could not load metafile")
	}
	defer closeMetaFile(m)

	oldcontracts, err := loadMetaContracts(m, allContractsDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer oldcontracts.Close()

	c := makeLimitedClient()
	if synced, err := c.Synced(); !synced && err == nil {
		return errors.New("blockchain is not synchronized")
	}
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}
	op := renterutil.MigrateDirect(newcontracts, oldcontracts, m, c, currentHeight)
	return trackMigrateFile(metaPath, op)
}

func migrateDirDirect(allContractsDir, newContractsDir, metaDir string) error {
	newcontracts, err := renter.LoadContracts(newContractsDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer newcontracts.Close()

	c := makeLimitedClient()
	if synced, err := c.Synced(); !synced && err == nil {
		return errors.New("blockchain is not synchronized")
	}
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}
	fileIter := renterutil.NewRecursiveMigrateDirIter(metaDir, allContractsDir)
	op := renterutil.MigrateDirDirect(newcontracts, fileIter, c, currentHeight)
	return trackMigrateDir(op)
}

func migrateRemote(newContractsDir, metaPath string) error {
	newcontracts, err := renter.LoadContracts(newContractsDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer newcontracts.Close()

	m, err := renter.OpenMetaFile(metaPath)
	if err != nil {
		return errors.Wrap(err, "could not load metafile")
	}
	defer closeMetaFile(m)

	oldcontracts, err := loadMetaContracts(m, newContractsDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer oldcontracts.Close()

	c := makeLimitedClient()
	if synced, err := c.Synced(); !synced && err == nil {
		return errors.New("blockchain is not synchronized")
	}
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}
	op := renterutil.MigrateRemote(newcontracts, oldcontracts, m, c, currentHeight)
	return trackMigrateFile(metaPath, op)
}

func migrateDirRemote(newContractsDir, metaDir string) error {
	newcontracts, err := renter.LoadContracts(newContractsDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer newcontracts.Close()

	c := makeLimitedClient()
	if synced, err := c.Synced(); !synced && err == nil {
		return errors.New("blockchain is not synchronized")
	}
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}
	fileIter := renterutil.NewRecursiveMigrateDirIter(metaDir, newContractsDir)
	op := renterutil.MigrateDirRemote(newcontracts, fileIter, c, currentHeight)
	return trackMigrateDir(op)
}
