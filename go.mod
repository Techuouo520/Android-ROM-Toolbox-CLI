module artb

go 1.27.1

require (
	artb/xz v0.0.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.9
	github.com/ssut/payload-dumper-go v0.0.0-20260820001620-05fe59e21c9f
	go.yaml.in/yaml/v3 v3.0.4
)

require (
	github.com/andybalholm/brotli v1.2.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/valyala/gozstd v1.26.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/ssut/payload-dumper-go => ./upstream/payload-dumper-go

replace artb/xz => ./xz
