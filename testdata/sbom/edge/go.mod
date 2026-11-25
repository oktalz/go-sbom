module example.com/edge

go 1.22

require (
	github.com/dual/lib v1.0.0
	github.com/inc/lib v2.0.0+incompatible
	github.com/old/lib v1.0.0
)

replace github.com/old/lib => ./fork
