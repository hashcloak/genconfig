# Genconfig

This is a fork of [katzenpost/genconfig](https://github.com/katzenpost/genconfig) with a few changes to support adding additional CBORPlugins and to make it easier to work with docker containers.

## Installation

Requires `go` version `1.13`.

## Usage

```bash
$ go run main.go -a <your authority ip address>
$ go run main.go --help
  -a string
    	Non-voting authority public ip address. (default "127.0.0.1")
  -b string
    	Path to for DataDir in the config files. (default "/conf")
  -n int
    	Number of mixes. (default 6)
  -nv int
    	Number of voting authorities. (default 3)
  -o string
    	Output path of the generate config files. (default "./output")
  -p int
    	Number of providers. (default 2)
  -v	Generate voting configuration.
```

This will generate a directory named `output` with all the configs needed to run a mixnet. It currently only generates the following configs:
- 1 nonvoting authority
- 2 providers with Meson support
- 6 mix nodesUsage of /tmp/go-build169833180/b001/exe/main: