module lukechampine.com/us

go 1.16

retract [v1.13.0, v1.13.1] // pushed accidentally

require (
	filippo.io/edwards25519 v1.0.0
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da
	gitlab.com/NebulousLabs/encoding v0.0.0-20200604091946-456c3dc907fe
	gitlab.com/NebulousLabs/log v0.0.0-20200604091839-0ba4a941cdc2
	gitlab.com/NebulousLabs/siamux v0.0.0-20210409140711-e667c5f458e4 // for testing mux compatibility
	go.etcd.io/bbolt v1.3.6
	go.sia.tech/siad v1.5.7
	golang.org/x/crypto v0.1.0
	golang.org/x/sys v0.1.0
	lukechampine.com/frand v1.4.2
)
