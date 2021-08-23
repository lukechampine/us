module lukechampine.com/us

go 1.16

retract [v1.13.0, v1.13.1] // pushed accidentally

require (
	filippo.io/edwards25519 v1.0.0-beta.2
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da
	gitlab.com/NebulousLabs/Sia v1.5.6
	gitlab.com/NebulousLabs/encoding v0.0.0-20200604091946-456c3dc907fe
	gitlab.com/NebulousLabs/log v0.0.0-20200604091839-0ba4a941cdc2
	gitlab.com/NebulousLabs/siamux v0.0.0-20210301103357-b3e1da6f3ee1 // for testing mux compatibility
	go.etcd.io/bbolt v1.3.6
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/sys v0.0.0-20210330210617-4fbd30eecc44
	lukechampine.com/frand v1.4.2
)
