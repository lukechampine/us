/**
 * Matrix Algebra over an 8-bit Galois Field
 *
 * Copyright 2015, Klaus Post
 * Copyright 2015, Backblaze, Inc.
 */

package reedsolomon

import (
	"errors"
)

var (
	errInvalidRowSize = errors.New("invalid row size")
	errInvalidColSize = errors.New("invalid column size")
	errMatrixSize     = errors.New("matrix sizes do not match")
	errSingular       = errors.New("matrix is singular")
	errNotSquare      = errors.New("only square matrices can be inverted")
)

// byte[row][col]
type matrix [][]byte

// newMatrix returns a matrix of zeros.
func newMatrix(rows, cols int) matrix {
	if rows <= 0 {
		panic(errInvalidRowSize)
	}
	if cols <= 0 {
		panic(errInvalidColSize)
	}
	m := matrix(make([][]byte, rows))
	for i := range m {
		m[i] = make([]byte, cols)
	}
	return m
}

// IdentityMatrix returns an identity matrix of the given size.
func identityMatrix(size int) matrix {
	m := newMatrix(size, size)
	for i := range m {
		m[i][i] = 1
	}
	return m
}

// Multiply multiplies this matrix (the one on the left) by another
// matrix (the one on the right) and returns a new matrix with the result.
func (m matrix) Multiply(right matrix) matrix {
	if len(m[0]) != len(right) {
		panic(errMatrixSize)
	}
	result := newMatrix(len(m), len(right[0]))
	for r, row := range result {
		for c := range row {
			var value byte
			for i := range m[0] {
				value ^= galMultiply(m[r][i], right[i][c])
			}
			result[r][c] = value
		}
	}
	return result
}

// Augment returns the concatenation of this matrix and the matrix on the right.
func (m matrix) Augment(right matrix) matrix {
	if len(m) != len(right) {
		panic(errMatrixSize)
	}

	result := newMatrix(len(m), len(m[0])+len(right[0]))
	for r, row := range m {
		for c := range row {
			result[r][c] = m[r][c]
		}
		cols := len(m[0])
		for c := range right[0] {
			result[r][cols+c] = right[r][c]
		}
	}
	return result
}

// Returns a part of this matrix. Data is copied.
func (m matrix) SubMatrix(rmin, cmin, rmax, cmax int) matrix {
	result := newMatrix(rmax-rmin, cmax-cmin)
	// OPTME: If used heavily, use copy function to copy slice
	for r := rmin; r < rmax; r++ {
		for c := cmin; c < cmax; c++ {
			result[r-rmin][c-cmin] = m[r][c]
		}
	}
	return result
}

// SwapRows Exchanges two rows in the matrix.
func (m matrix) SwapRows(r1, r2 int) {
	if r1 < 0 || len(m) <= r1 || r2 < 0 || len(m) <= r2 {
		panic(errInvalidRowSize)
	}
	m[r2], m[r1] = m[r1], m[r2]
}

// IsSquare will return true if the matrix is square
// and nil if the matrix is square
func (m matrix) IsSquare() bool {
	return len(m) == len(m[0])
}

// Invert returns the inverse of this matrix.
// Returns ErrSingular when the matrix is singular and doesn't have an inverse.
// The matrix must be square, otherwise ErrNotSquare is returned.
func (m matrix) Invert() (matrix, error) {
	if !m.IsSquare() {
		panic(errNotSquare)
	}

	size := len(m)
	work := m.Augment(identityMatrix(size))

	err := work.gaussianElimination()
	if err != nil {
		return nil, err
	}

	return work.SubMatrix(0, size, size, size*2), nil
}

func (m matrix) gaussianElimination() error {
	rows := len(m)
	columns := len(m[0])
	// Clear out the part below the main diagonal and scale the main
	// diagonal to be 1.
	for r := 0; r < rows; r++ {
		// If the element on the diagonal is 0, find a row below
		// that has a non-zero and swap them.
		if m[r][r] == 0 {
			for rowBelow := r + 1; rowBelow < rows; rowBelow++ {
				if m[rowBelow][r] != 0 {
					m.SwapRows(r, rowBelow)
					break
				}
			}
		}
		// If we couldn't find one, the matrix is singular.
		if m[r][r] == 0 {
			return errSingular
		}
		// Scale to 1.
		if m[r][r] != 1 {
			scale := galDivide(1, m[r][r])
			for c := 0; c < columns; c++ {
				m[r][c] = galMultiply(m[r][c], scale)
			}
		}
		// Make everything below the 1 be a 0 by subtracting
		// a multiple of it.  (Subtraction and addition are
		// both exclusive or in the Galois field.)
		for rowBelow := r + 1; rowBelow < rows; rowBelow++ {
			if m[rowBelow][r] != 0 {
				scale := m[rowBelow][r]
				for c := 0; c < columns; c++ {
					m[rowBelow][c] ^= galMultiply(scale, m[r][c])
				}
			}
		}
	}

	// Now clear the part above the main diagonal.
	for d := 0; d < rows; d++ {
		for rowAbove := 0; rowAbove < d; rowAbove++ {
			if m[rowAbove][d] != 0 {
				scale := m[rowAbove][d]
				for c := 0; c < columns; c++ {
					m[rowAbove][c] ^= galMultiply(scale, m[d][c])
				}

			}
		}
	}
	return nil
}

// Create a Vandermonde matrix, which is guaranteed to have the
// property that any subset of rows that forms a square matrix
// is invertible.
func vandermonde(rows, cols int) matrix {
	result := newMatrix(rows, cols)
	for r, row := range result {
		for c := range row {
			result[r][c] = galExp(byte(r), c)
		}
	}
	return result
}
