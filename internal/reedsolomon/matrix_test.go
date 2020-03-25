/**
 * Unit tests for Matrix
 *
 * Copyright 2015, Klaus Post
 * Copyright 2015, Backblaze, Inc.  All rights reserved.
 */

package reedsolomon

import (
	"reflect"
	"testing"
)

// TestMatrixIdentity - validates the method for returning identity matrix of given size.
func TestMatrixIdentity(t *testing.T) {
	m := identityMatrix(3)
	exp := matrix{{1, 0, 0}, {0, 1, 0}, {0, 0, 1}}
	if !reflect.DeepEqual(m, exp) {
		t.Fatal(m, "!=", exp)
	}
}

// Tests validate the output of matrix multiplication method.
func TestMatrixMultiply(t *testing.T) {
	m1 := matrix([][]byte{
		[]byte{1, 2},
		[]byte{3, 4},
	})
	m2 := matrix([][]byte{
		[]byte{5, 6},
		[]byte{7, 8},
	})
	actual := m1.Multiply(m2)
	exp := matrix{{11, 22}, {19, 42}}
	if !reflect.DeepEqual(actual, exp) {
		t.Fatal(actual, "!=", exp)
	}
}

// Tests validate the output of the method with computes inverse of matrix.
func TestMatrixInverse(t *testing.T) {
	testCases := []struct {
		matrixData matrix
		// expected inverse matrix.
		expectedResult matrix
		// flag indicating whether the test should pass.
		shouldPass  bool
		expectedErr error
	}{
		// Test case - 1.
		// Test case validating inverse of the input Matrix.
		{
			// input data to construct the matrix.
			matrix{
				[]byte{56, 23, 98},
				[]byte{3, 100, 200},
				[]byte{45, 201, 123},
			},
			// expected Inverse matrix.
			matrix{{175, 133, 33}, {130, 13, 245}, {112, 35, 126}},
			// test is expected to pass.
			true,
			nil,
		},
		// Test case - 2.
		// Test case validating inverse of the input Matrix.
		{
			// input data to construct the matrix.
			matrix{
				[]byte{1, 0, 0, 0, 0},
				[]byte{0, 1, 0, 0, 0},
				[]byte{0, 0, 0, 1, 0},
				[]byte{0, 0, 0, 0, 1},
				[]byte{7, 7, 6, 6, 1},
			},
			// expectedInverse matrix.
			matrix{
				{1, 0, 0, 0, 0},
				{0, 1, 0, 0, 0},
				{123, 123, 1, 122, 122},
				{0, 0, 1, 0, 0},
				{0, 0, 0, 1, 0},
			},
			// test is expected to pass.
			true,
			nil,
		},
		// Test case with singular matrix.
		// expected to fail with error errSingular.
		{

			matrix{
				[]byte{4, 2},
				[]byte{12, 6},
			},
			nil,
			false,
			errSingular,
		},
	}

	for i, testCase := range testCases {
		m := matrix(testCase.matrixData)
		actualResult, actualErr := m.Invert()
		if actualErr != nil && testCase.shouldPass {
			t.Errorf("Test %d: Expected to pass, but failed with: <ERROR> %s", i+1, actualErr.Error())
		}
		if actualErr == nil && !testCase.shouldPass {
			t.Errorf("Test %d: Expected to fail with <ERROR> \"%s\", but passed instead.", i+1, testCase.expectedErr)
		}
		// Failed as expected, but does it fail for the expected reason.
		if actualErr != nil && !testCase.shouldPass {
			if testCase.expectedErr != actualErr {
				t.Errorf("Test %d: Expected to fail with error \"%s\", but instead failed with error \"%s\" instead.", i+1, testCase.expectedErr, actualErr)
			}
		}
		// Test passes as expected, but the output values
		// are verified for correctness here.
		if actualErr == nil && testCase.shouldPass {
			if !reflect.DeepEqual(testCase.expectedResult, actualResult) {
				t.Errorf("Test %d: The inverse matrix doesn't match the expected result", i+1)
			}
		}
	}
}
