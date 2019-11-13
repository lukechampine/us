// Package renterutil provides convenience functions for common renter
// actions.
package renterutil // import "lukechampine.com/us/renter/renterutil"

import (
	"errors"
)

// assume metafiles have this extension
const metafileExt = ".usa"

// ErrCanceled indicates that the Operation was canceled.
var ErrCanceled = errors.New("canceled")
