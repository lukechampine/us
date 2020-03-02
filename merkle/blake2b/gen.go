// +build ignore

package main

import (
	"fmt"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

// global vars
var (
	shuffleRot16       Mem
	shuffleRot24       Mem
	shuffleRot32       Mem
	shuffleFirstVector Mem
	shuffleLastVector  Mem
	stride64           Mem
	initState          Mem
)

func main() {
	genGlobals()
	genHashBlocksAVX2()

	Generate()
}

func genGlobals() {
	shuffleRot16 = GLOBL("shuffle_rot16", RODATA|NOPTR)
	for i := 0; i < 4; i++ {
		DATA(i*8, U64(0x0100070605040302+0x0808080808080808*i))
	}
	shuffleRot24 = GLOBL("shuffle_rot24", RODATA|NOPTR)
	for i := 0; i < 4; i++ {
		DATA(i*8, U64(0x0201000706050403+0x0808080808080808*i))
	}
	shuffleRot32 = GLOBL("shuffle_rot32", RODATA|NOPTR)
	for i := 0; i < 4; i++ {
		DATA(i*8, U64(0x0302010007060504+0x0808080808080808*i))
	}

	shuffleFirstVector = GLOBL("shuffle_first_vector", RODATA|NOPTR)
	for i := 0; i < 4; i++ {
		DATA(i*8, U64(0x06050403020100FF+0x0808080808080800*uint64(i)))
	}
	shuffleLastVector = GLOBL("shuffle_last_vector", RODATA|NOPTR)
	for i := 0; i < 4; i++ {
		DATA(i*8, U64(0xFFFFFFFFFFFFFF07+0x0000000000000008*uint64(i)))
	}
	stride64 = GLOBL("stride_64", RODATA|NOPTR)
	for i := 0; i < 4; i++ {
		DATA(i*8, U64(i*64))
	}

	initState = GLOBL("init_state", RODATA|NOPTR)
	for i, v := range [16]U64{
		// h0 .. h7
		0x6a09e667f2bdc928,
		0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b,
		0xa54ff53a5f1d36f1,
		0x510e527fade682d1,
		0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b,
		0x5be0cd19137e2179,
		// iv ^ parameter block
		0x6a09e667f3bcc908,
		0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b,
		0xa54ff53a5f1d36f1,
		0x510e527fade68290, // xor'd with 65 (input length)
		0x9b05688c2b3e6c1f,
		0xe07c265404be4294, // xor'd with ~0 (final block)
		0x5be0cd19137e2179,
	} {
		DATA(i*8, v)
	}
}

func genHashBlocksAVX2() {
	TEXT("hashBlocksAVX2", NOSPLIT, "func(outs *[4][32]byte, msgs *[4][64]byte, prefix uint64)")
	Pragma("noescape")
	msgs := Mem{Base: Load(Param("msgs"), GP64())}
	outs := Mem{Base: Load(Param("outs"), GP64())}
	prefix, _ := Param("prefix").Resolve()
	vs := [16]VecVirtual{
		YMM(), YMM(), YMM(), YMM(),
		YMM(), YMM(), YMM(), YMM(),
		YMM(), YMM(), YMM(), YMM(),
		YMM(), YMM(), YMM(), YMM(),
	}

	// store transposed msgs on the stack
	block := AllocLocal(9 * 32)

	{
		Comment("Transpose message vectors into the stack")
		// strided loads
		VMOVDQU(stride64, vs[15])
		for i := range vs[:9] {
			var offset int
			switch i {
			case 0:
				offset = 0
			default:
				offset = i*8 - 1
			case 8:
				offset = (i - 1) * 8
			}
			strideMem := msgs.Offset(offset).Idx(vs[15], 1)
			// VPGATHERQQ sets vs[14] to all zeros on success, so we need to
			// reset it each time
			VPCMPEQD(vs[14], vs[14], vs[14]) // fastest way to set all bits to 1
			VPGATHERQQ(vs[14], strideMem, vs[i])
		}
		// adjust the first and last vectors: the words in the first vector need
		// to be prefixed, and the words in the last vector need to contain only
		// their first byte
		VPSHUFB(shuffleFirstVector, vs[0], vs[0])
		VPBROADCASTQ(prefix.Addr, vs[15])
		VPOR(vs[0], vs[15], vs[0])
		VPSHUFB(shuffleLastVector, vs[8], vs[8])
		// store
		for i, v := range vs[:9] {
			VMOVDQU(v, block.Offset(i*32))
		}
	}

	{
		Comment("Round setup")
		for i := range vs {
			VPBROADCASTQ(initState.Offset(i*8), vs[i])
		}
		tmp := vs[8]
		spillMem := AllocLocal(32)
		VMOVDQU(vs[8], spillMem)

		for i := 0; i < 12; i++ {
			Comment(fmt.Sprintf("Round %v", i+1))
			msgs := permutation(block, i)
			round(vs, msgs, tmp, spillMem)
		}

		Comment("Finalize")
		VMOVDQU(spillMem, vs[8])
		for i := range vs[:4] {
			VPXOR(vs[i], vs[i+8], vs[i])
			VPBROADCASTQ(initState.Offset(i*8), vs[i+8])
			VPXOR(vs[i], vs[i+8], vs[i])
		}
	}

	{
		Comment("Transpose state vectors into outs")
		// Interleave 0 and 1
		VPUNPCKLQDQ(vs[1], vs[0], vs[4])
		VPUNPCKHQDQ(vs[1], vs[0], vs[5])
		// Interleave 2 and 3
		VPUNPCKLQDQ(vs[3], vs[2], vs[6])
		VPUNPCKHQDQ(vs[3], vs[2], vs[7])
		// Interleave 01 and 23
		VINSERTI128(Imm(1), vs[6].AsX(), vs[4], vs[0])
		VINSERTI128(Imm(1), vs[7].AsX(), vs[5], vs[1])
		VPERM2I128(Imm(0x31), vs[6], vs[4], vs[2])
		VPERM2I128(Imm(0x31), vs[7], vs[5], vs[3])
		for i, v := range vs[:4] {
			VMOVDQU(v, outs.Offset(i*32))
		}
	}

	RET()
}

func round(sv [16]VecVirtual, mv [16]Mem, tmp VecVirtual, spillMem Mem) {
	gSpill(sv[0], sv[4], sv[8], sv[12], mv[0], mv[1], tmp, spillMem)
	g(sv[1], sv[5], sv[9], sv[13], mv[2], mv[3], tmp)
	g(sv[2], sv[6], sv[10], sv[14], mv[4], mv[5], tmp)
	g(sv[3], sv[7], sv[11], sv[15], mv[6], mv[7], tmp)
	g(sv[0], sv[5], sv[10], sv[15], mv[8], mv[9], tmp)
	g(sv[1], sv[6], sv[11], sv[12], mv[10], mv[11], tmp)
	gSpill(sv[2], sv[7], sv[8], sv[13], mv[12], mv[13], tmp, spillMem)
	g(sv[3], sv[4], sv[9], sv[14], mv[14], mv[15], tmp)
}

func rotr63(v, tmp VecVirtual) {
	VPSRLQ(Imm(63), v, tmp)
	VPSLLQ(Imm(1), v, v)
	VPOR(v, tmp, v)
}

// sentinel value so that g/gSpill can skip a VPADDQ; message vectors m8..m15
// contain all zeros, so we don't need to add them.
var zeroMem Mem

func g(a, b, c, d VecVirtual, mx, my Mem, tmp VecVirtual) {
	VPADDQ(a, b, a)
	if mx != zeroMem {
		VPADDQ(mx, a, a)
	}
	VPXOR(d, a, d)
	VPSHUFB(shuffleRot32, d, d)
	VPADDQ(c, d, c)
	VPXOR(b, c, b)
	VPSHUFB(shuffleRot24, b, b)
	VPADDQ(a, b, a)
	if my != zeroMem {
		VPADDQ(my, a, a)
	}
	VPXOR(d, a, d)
	VPSHUFB(shuffleRot16, d, d)
	VPADDQ(c, d, c)
	VPXOR(b, c, b)
	rotr63(b, tmp)
}

// in gSpill, c is v[8], so we need to reload and spill it
func gSpill(a, b, c, d VecVirtual, mx, my Mem, tmp VecVirtual, spillMem Mem) {
	VPADDQ(a, b, a)
	if mx != zeroMem {
		VPADDQ(mx, a, a)
	}
	VPXOR(d, a, d)
	VPSHUFB(shuffleRot32, d, d)
	VPADDQ(spillMem, d, c) // reload c
	VPXOR(b, c, b)
	VPSHUFB(shuffleRot24, b, b)
	VPADDQ(a, b, a)
	if my != zeroMem {
		VPADDQ(my, a, a)
	}
	VPXOR(d, a, d)
	VPSHUFB(shuffleRot16, d, d)
	VPADDQ(c, d, c)
	VPXOR(b, c, b)
	VMOVDQU(c, spillMem) // done with c, spill it
	rotr63(b, tmp)
}

// Each round uses a different permutation of the message vectors. Since we're
// inlining everything, we can permute the memory *locations* instead of the
// memory itself.
func permutation(msg Mem, n int) [16]Mem {
	perms := [12][16]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
		{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
		{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
		{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
		{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
		{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
		{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
		{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
		{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	}
	var m [16]Mem
	for i, j := range perms[n] {
		if j < 9 {
			m[i] = msg.Offset(j * 32)
		} else {
			m[i] = zeroMem
		}
	}
	return m
}
