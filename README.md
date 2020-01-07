# Genconfig

This is a fork of [katzenpost/genconfig](https://github.com/katzenpost/genconfig) with a few changes to support adding additional CBORPlugins and to make it easier to work with docker containers.

## Installation

Requires `go` version `1.13`.

## Usage

```bash
$ go run main.go -a <your authority ip address>
```

This will generate a directory named `output` with all the configs needed to run a mixnet. It currently only generates the following configs:
- 1 nonvoting authority
- 2 providers with Meson support
- 6 mix nodes