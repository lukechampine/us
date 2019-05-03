package main

import (
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/renterutil"
	"lukechampine.com/us/renterhost"
)

func metainfo(m renter.MetaIndex, shards [][]renter.SectorSlice) {
	var uploaded int64
	for _, shard := range shards {
		for _, s := range shard {
			uploaded += int64(s.NumSegments * merkle.SegmentSize)
		}
	}
	redundancy := float64(len(m.Hosts)) / float64(m.MinShards)
	pctFullRedundancy := 100 * float64(uploaded) / (float64(m.Filesize) * redundancy)
	if m.Filesize == 0 || pctFullRedundancy > 100 {
		pctFullRedundancy = 100
	}

	fmt.Printf(`Filesize:   %v
Redundancy: %v-of-%v (%0.2gx replication)
Uploaded:   %v (%0.2f%% of full redundancy)
`, filesizeUnits(m.Filesize), m.MinShards, len(m.Hosts), redundancy,
		filesizeUnits(uploaded), pctFullRedundancy)
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

	c := makeLimitedClient()
	if synced, err := c.Synced(); !synced && err == nil {
		return errors.New("blockchain is not synchronized")
	}
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}

	dir, name := filepath.Dir(metaPath), strings.TrimSuffix(filepath.Base(metaPath), ".usa")
	fs := renterutil.NewFileSystem(dir, contracts, c, currentHeight)
	defer fs.Close()
	pf, err := fs.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_TRUNC, stat.Mode(), minShards)
	if err != nil {
		return err
	}
	defer pf.Close()
	return trackUpload(pf, f)
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
	fs := renterutil.NewFileSystem(dir, contracts, c, currentHeight)
	defer fs.Close()

	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() || err != nil {
			return nil
		}
		fs.MkdirAll(path, 0700)
		pf, err := fs.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_TRUNC, info.Mode(), minShards)
		if err != nil {
			return err
		}
		defer pf.Close()
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		return trackUpload(pf, f)
	})
}

func resumeuploadmetafile(f *os.File, contractDir, metaPath string) error {
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

	dir, name := filepath.Dir(metaPath), strings.TrimSuffix(filepath.Base(metaPath), ".usa")
	fs := renterutil.NewFileSystem(dir, contracts, c, currentHeight)
	defer fs.Close()
	pf, err := fs.OpenFile(name, os.O_APPEND, 0, 0)
	if err != nil {
		return err
	}
	defer pf.Close()
	stat, _ := pf.Stat()
	if _, err := f.Seek(stat.Size(), io.SeekStart); err != nil {
		return err
	}
	return trackUpload(pf, f)
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
	// resume at end of file
	offset := stat.Size()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	if _, err := pf.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	return trackDownload(f, pf, offset)
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
	fs := renterutil.NewFileSystem(dir, contracts, makeLimitedClient(), 0)
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
	fs := renterutil.NewFileSystem(dir, contracts, makeLimitedClient(), 0)
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
	fs := renterutil.NewFileSystem(metaDir, contracts, makeLimitedClient(), 0)
	defer fs.Close()

	return filepath.Walk(metaDir, func(metaPath string, info os.FileInfo, err error) error {
		if info.IsDir() || err != nil {
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
