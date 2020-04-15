# MobProtID
[![CircleCI](https://circleci.com/gh/arbitraryrw/MobProtID.svg?style=shield)](https://circleci.com/gh/arbitraryrw/MobProtID)
[![Go Report Card](https://goreportcard.com/badge/github.com/arbitraryrw/MobProtID?style=flat-square)](https://goreportcard.com/report/github.com/arbitraryrw/MobProtID)
[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/arbitraryrw/MobProtID)
[![Release](https://img.shields.io/github/release/golang-standards/project-layout.svg?style=flat-square)](https://github.com/arbitraryrw/MobProtID/releases/latest)

A simple Mobile Analysis POC tool to practice programming in [golang](https://golang.org/doc/code.html).

### Usage
Run the compiled binary and specify a target binary to analyse as seen below:

```go
cmd/mobprotid -target=<target binary path>
```

### Testing
To recursively run all unit tests in the project run the following go command in the project root directory:

```go
go test ./...
```
### Dependencies
- [r2pipe-go](https://github.com/radareorg/radare2-r2pipe/tree/master/go)
- [radare2](https://github.com/radareorg/radare2)
- [go-yara](https://github.com/hillu/go-yara)
- [yara](https://virustotal.github.io/yara/)

### Useful Go References
- [project-layout](https://github.com/golang-standards/project-layout)
- [fmt docs](https://golang.org/pkg/fmt/)
- [testing docs](https://golang.org/pkg/testing/)
- [general coding docs](https://golang.org/doc/code.html)
- [gobyexample](https://gobyexample.com/)
- [r2pipe-go docs](https://godoc.org/github.com/radare/r2pipe-go)
- [go-yara docs](https://godoc.org/github.com/hillu/go-yara)
- [Installing yara](https://yara.readthedocs.io/en/stable/gettingstarted.html)

### License
[GNU General Public License v3.0](https://github.com/arbitraryrw/MobProtID/blob/master/LICENSE)