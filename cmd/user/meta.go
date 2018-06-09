package main

import (
	"fmt"
	"io"
	"log"
	"math"
	"os"

	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/renterutil"

	"github.com/pkg/errors"
)

func metainfo(m renter.MetaIndex, shards [][]renter.SectorSlice) {
	var uploaded int64
	for _, shard := range shards {
		for _, slice := range shard {
			uploaded += int64(slice.Length)
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

func uploadmetafile(f *os.File, minShards int, contractDir, metaPath string) error {
	contracts, err := loadContracts(contractDir)
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
		return errors.Wrap(err, "could not create meta file")
	}
	defer func() {
		if err := m.Archive(metaPath); err != nil {
			log.Println("ERROR: could not create meta file archive")
		}
	}()

	c := makeClient()
	if !c.Synced() {
		return errors.New("blockchain is not synchronized")
	}
	op := renterutil.Upload(f, contracts, m, c.Scan, c.ChainHeight())
	return trackUpload(f.Name(), op)
}

func uploadmetadir(dir, metaDir, contractDir string, minShards int) error {
	contracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	c := makeClient()
	if !c.Synced() {
		return errors.New("blockchain is not synchronized")
	}

	fileIter := renterutil.NewRecursiveFileIter(dir, metaDir)
	op := renterutil.UploadDir(fileIter, contracts, minShards, c.Scan, c.ChainHeight())
	return trackUploadDir(op)
}

func resumeuploadmetafile(f *os.File, contractDir, metaPath string) error {
	contracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	m, err := renter.ExtractMetaFile(metaPath)
	if err != nil {
		return errors.Wrap(err, "could not load meta file")
	}
	defer func() {
		if err := m.Archive(metaPath); err != nil {
			log.Println("ERROR: could not create meta file archive:", err)
		}
	}()

	c := makeClient()
	if !c.Synced() {
		return errors.New("blockchain is not synchronized")
	}
	op := renterutil.Upload(f, contracts, m, c.Scan, c.ChainHeight())
	return trackUpload(f.Name(), op)
}

func downloadmetafile(f *os.File, contractDir, metaPath string) error {
	contracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	if ok, err := renter.MetaFileCanDownload(metaPath); err == nil && !ok {
		return errors.New("file is not sufficiently uploaded")
	}

	m, err := renter.ExtractMetaFile(metaPath)
	if err != nil {
		return errors.Wrap(err, "could not load meta file")
	}
	defer func() {
		if err := m.Archive(metaPath); err != nil {
			log.Println("ERROR: could not create meta file archive:", err)
		}
	}()

	c := makeClient()
	op := renterutil.Download(f, contracts, m, c.Scan)
	return trackDownload(f.Name(), op)
}

func downloadmetastream(w io.Writer, contractDir, metaPath string) error {
	contracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	if ok, err := renter.MetaFileCanDownload(metaPath); err == nil && !ok {
		return errors.New("file is not sufficiently uploaded")
	}

	m, err := renter.ExtractMetaFile(metaPath)
	if err != nil {
		return errors.Wrap(err, "could not load meta file")
	}
	defer func() {
		if err := m.Archive(metaPath); err != nil {
			log.Println("ERROR: could not create meta file archive:", err)
		}
	}()

	c := makeClient()
	op := renterutil.DownloadStream(w, contracts, m, c.Scan)
	return trackDownloadStream(op)
}

func downloadmetadir(dir, contractDir, metaDir string) error {
	contracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	c := makeClient()
	metafileIter := renterutil.NewRecursiveMetaFileIter(metaDir, dir)
	op := renterutil.DownloadDir(metafileIter, contracts, c.Scan)
	return trackDownloadDir(op)
}

func checkupMeta(contractDir, metaPath string) error {
	contracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	m, err := renter.ExtractMetaFile(metaPath)
	if err != nil {
		return errors.Wrap(err, "could not load meta file")
	}
	defer func() {
		if err := m.Archive(metaPath); err != nil {
			log.Println("ERROR: could not create meta file archive")
		}
	}()

	c := makeClient()
	for r := range renterutil.Checkup(contracts, m, c.Scan) {
		if r.Error != nil {
			fmt.Printf("FAIL Host %v:\n\t%v\n", r.Host.ShortKey(), r.Error)
		} else {
			fmt.Printf("OK   Host %v: Latency %0.3fms, Bandwidth %0.3f Mbps\n",
				r.Host.ShortKey(), r.Latency.Seconds()*1000, r.Bandwidth)
		}
	}

	return nil
}

func migrateFile(f *os.File, contractDir, metaPath string) error {
	newcontracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer newcontracts.Close()

	m, err := renter.ExtractMetaFile(metaPath)
	if err != nil {
		return errors.Wrap(err, "could not load meta file")
	}
	defer func() {
		if err := m.Archive(metaPath); err != nil {
			log.Println("ERROR: could not create meta file archive:", err)
		}
	}()

	c := makeClient()
	if !c.Synced() {
		return errors.New("blockchain is not synchronized")
	}
	op := renterutil.MigrateFile(f, newcontracts, m, c.Scan, c.ChainHeight())
	return trackMigrateFile(metaPath, op)
}

func migrateDirFile(dir, contractDir, metaDir string) error {
	newcontracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer newcontracts.Close()

	c := makeClient()
	if !c.Synced() {
		return errors.New("blockchain is not synchronized")
	}
	metafileIter := renterutil.NewRecursiveMetaFileIter(metaDir, dir)
	op := renterutil.MigrateDirFile(newcontracts, metafileIter, c.Scan, c.ChainHeight())
	return trackMigrateDir(op)
}

func migrateDirect(contractDir, metaPath string) error {
	newcontracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer newcontracts.Close()

	m, err := renter.ExtractMetaFile(metaPath)
	if err != nil {
		return errors.Wrap(err, "could not load meta file")
	}
	defer func() {
		if err := m.Archive(metaPath); err != nil {
			log.Println("ERROR: could not create meta file archive:", err)
		}
	}()

	oldcontracts, err := loadMetaContracts(m, contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer oldcontracts.Close()

	c := makeClient()
	if !c.Synced() {
		return errors.New("blockchain is not synchronized")
	}
	op := renterutil.MigrateDirect(newcontracts, oldcontracts, m, c.Scan, c.ChainHeight())
	return trackMigrateFile(metaPath, op)
}

func migrateDirDirect(contractDir, metaDir string) error {
	newcontracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer newcontracts.Close()

	c := makeClient()
	if !c.Synced() {
		return errors.New("blockchain is not synchronized")
	}
	fileIter := renterutil.NewRecursiveMigrateDirIter(metaDir, contractDir)
	op := renterutil.MigrateDirDirect(newcontracts, fileIter, c.Scan, c.ChainHeight())
	return trackMigrateDir(op)
}

func migrateRemote(contractDir, metaPath string) error {
	newcontracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer newcontracts.Close()

	m, err := renter.ExtractMetaFile(metaPath)
	if err != nil {
		return errors.Wrap(err, "could not load meta file")
	}
	defer func() {
		if err := m.Archive(metaPath); err != nil {
			log.Println("ERROR: could not create meta file archive:", err)
		}
	}()

	oldcontracts, err := loadMetaContracts(m, contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer oldcontracts.Close()

	c := makeClient()
	if !c.Synced() {
		return errors.New("blockchain is not synchronized")
	}
	op := renterutil.MigrateRemote(newcontracts, oldcontracts, m, c.Scan, c.ChainHeight())
	return trackMigrateFile(metaPath, op)
}

func migrateDirRemote(contractDir, metaDir string) error {
	newcontracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer newcontracts.Close()

	c := makeClient()
	if !c.Synced() {
		return errors.New("blockchain is not synchronized")
	}
	fileIter := renterutil.NewRecursiveMigrateDirIter(metaDir, contractDir)
	op := renterutil.MigrateDirRemote(newcontracts, fileIter, c.Scan, c.ChainHeight())
	return trackMigrateDir(op)
}
