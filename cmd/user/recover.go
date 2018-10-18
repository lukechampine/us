package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"lukechampine.com/us/renter"
)

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func recoverMeta(metapath string) error {
	metapath = filepath.Clean(metapath)
	var workdir string
	if strings.HasSuffix(metapath, "_workdir") {
		workdir = metapath
		metapath = strings.TrimSuffix(metapath, "_workdir")
	} else {
		workdir = metapath + "_workdir"
	}

	fmt.Println("Collecting info...")
	metaExists := exists(metapath)
	var metaIndex renter.MetaIndex
	var metaErr error
	if metaExists {
		fmt.Println(" - metafile exists")
		metaIndex, _, metaErr = renter.ReadMetaFileContents(metapath)
		if metaErr == nil {
			fmt.Println(" - metafile is valid")
		} else {
			fmt.Println(" - metafile is invalid or corrupted")
		}
	} else {
		fmt.Println(" - metafile does not exist")
	}

	workdirExists := exists(workdir)
	var workdirIndex renter.MetaIndex
	var workdirErr error
	if workdirExists {
		fmt.Println(" - workdir exists")
		workdirErr = func() error {
			if b, err := ioutil.ReadFile(filepath.Join(workdir, "index")); err != nil {
				return errors.Wrap(err, "could not read working directory index")
			} else if err := json.Unmarshal(b, &workdirIndex); err != nil {
				return errors.Wrap(err, "could not decode working directory index")
			}
			return nil
		}()
		if workdirErr == nil {
			fmt.Println(" - workdir index is valid")
		} else {
			fmt.Println(" - workdir index is invalid or corrupted")
		}
	} else {
		fmt.Println("workdir does not exist")
	}
	fmt.Println("Done collecting info.")
	fmt.Println()

	var actionDesc string
	var action func() error
	switch {

	// only the metafile exists -- no problem
	case metaExists && !workdirExists:
		if metaErr != nil {
			actionDesc = fmt.Sprintf(`The metafile is corrupted. Unless you know what you're doing, this won't be
easy to fix, and the file may be unrecoverable. The specific error was:
    %v`, metaErr)
		} else {
			actionDesc = `Everything seems to be in order.`
		}

	// only the workdir exists -- archive it
	case !metaExists && workdirExists:
		if workdirErr != nil {
			actionDesc = fmt.Sprintf(`The working directory is corrupted. Unless you know what you're doing, this
won't be easy to fix, and the file may be unrecoverable. The specific error
was:
    %v`, workdirErr)
		} else {
			actionDesc = `The working directory exists but the metafile does not, which usually means
that the process crashed while uploading a new file. The contents of the
working directory may or may not constitute a valid metafile.

Action that will be taken:
    Bundle the working directory into a (hopefully valid) metafile.
`
			action = func() error {
				return (&renter.MetaFile{
					MetaIndex: workdirIndex,
					Workdir:   workdir,
				}).Close()
			}
		}

	// both exist -- more complicated
	case metaExists && workdirExists:
		if metaErr != nil && workdirErr != nil {
			actionDesc = fmt.Sprintf(`Both the metafile and working directory exist, but are corrupted. Unless you
know what you're doing, this won't be easy to fix, and the file may be
unrecoverable. The specific errors were:
    %v
    %v`, metaErr, workdirErr)
			break
		}

		if metaErr != nil {
			actionDesc = fmt.Sprintf(`The metafile exists, but is corrupted. The specific error was:
    %v
This probably happened because a crash occurred while the metafile was being
overwritten with the contents of the working directory, which implies that the
working directory was in a consistent state at the time of the crash.

Action that will be taken:
    Bundle the working directory into a (hopefully valid) metafile.
    This will overwrite %v.
`, metaErr, metapath)
			action = func() error {
				return (&renter.MetaFile{
					MetaIndex: workdirIndex,
					Workdir:   workdir,
				}).Close()
			}
			break
		}

		if workdirErr != nil {
			actionDesc = `The metafile was extracted to working directory so that it could be modified,
but the working directory wasn't cleaned up, probably due to a crash. It looks
like the working directory is in an inconsistent state.

Action that will be taken:
    Delete the working directory.
`
			action = func() error { return os.RemoveAll(workdir) }
			break
		}

		// at this point, we know we want to delete the workdir, but give a
		// more helpful message based on the modtime of each index.
		if metaIndex.ModTime.After(workdirIndex.ModTime) {
			actionDesc = `The metafile was extracted to working directory so that it could be modified,
but the working directory wasn't cleaned up, probably due to a crash. It looks
like the contents of the working directory constitute a valid metafile. The
modtime of the metafile is more recent than the modtime of the working
directory, which means that the crash probably occurred after the working
directory was bundled into a metafile, but before the working directory was
deleted. Aside from the modtime, the contents of the metafile and the working
directory are likely identical.

Action that will be taken:
    Delete the working directory.
`
			action = func() error { return os.RemoveAll(workdir) }
			break
		}

		newmetapath := metapath + "_tmp"
		actionDesc = fmt.Sprintf(`The metafile was extracted to working directory so that it could be modified,
but the working directory wasn't cleaned up, probably due to a crash. It looks
like the contents of the working directory constitute a valid metafile. The
modtime of the metafile is not more recent than the modtime of the working
directory, which means that the crash probably occurred in the middle of a
file upload, and thus the working directory may be "ahead" of the metafile.
However, since the exact state of the working directory is unclear, it would
be unwise to overwrite the metafile, which is known to be valid.

Action that will be taken:
    Bundle the working directory into a (hopefully valid) metafile.
    This will NOT overwrite the existing metafile; it will create a
    new metafile at:
        %v
    Afterward, you should inspect both metafiles and determine which one
    to keep and which to delete.
`, newmetapath)
		action = func() error {
			return (&renter.MetaFile{
				MetaIndex: workdirIndex,
				Workdir:   workdir,
			}).Archive(newmetapath)
		}
	}

	fmt.Println(actionDesc)
	if action == nil {
		// no action required
		return nil
	}
again:
	fmt.Print("Proceed with this action? [y/n] ")
	var resp string
	fmt.Scanln(&resp)
	switch strings.ToLower(resp) {
	case "y", "yes":
		return action()
	case "n", "no":
		return nil
	default:
		goto again
	}
}
