# MobProtID
[![CircleCI](https://circleci.com/gh/arbitraryrw/MobProtID.svg?style=shield)](https://circleci.com/gh/arbitraryrw/MobProtID)
[![Go Report Card](https://goreportcard.com/badge/github.com/arbitraryrw/MobProtID?style=flat-square)](https://goreportcard.com/report/github.com/arbitraryrw/MobProtID)
[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/arbitraryrw/MobProtID)
[![Release](https://img.shields.io/github/release/golang-standards/project-layout.svg?style=flat-square)](https://github.com/arbitraryrw/MobProtID/releases/latest)

A simple Mobile Analysis tool to practice programming in [golang](https://golang.org/doc/code.html). Currently MobProtID supports static analysis of Android and iOS binaries for RASP protections.

### Usage
Run the compiled binary and specify a target binary to analyse as seen below:

```go
cmd/mobprotid -target=<target binary path>
```

### Testing
To recursively run all unit tests in the project run the following go command in the project root directory:

```go
go test ./...

// To clean the test cache:
go clean -testcache ./...
```

### Useful RASP References
- [MSTG](https://mobile-security.gitbook.io/mobile-security-testing-guide/)
- [MSTG Android - resiliency against reverse engineering](https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05j-testing-resiliency-against-reverse-engineering)
- [MSTG iOS - resiliency against reverse engineering](https://mobile-security.gitbook.io/mobile-security-testing-guide/ios-testing-guide/0x06j-testing-resiliency-against-reverse-engineering)
- [RedNaga](https://rednaga.io/)
- [iOS Anti-Reversing Defenses](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md)
- [Android Anti-Reversing Defenses](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md)

### Dependencies
- [r2pipe-go](https://github.com/radareorg/radare2-r2pipe/tree/master/go)
- [radare2](https://github.com/radareorg/radare2)
- [go-yara](https://github.com/hillu/go-yara)
- [yara](https://virustotal.github.io/yara/)
- [android sdk (cli tools)](https://developer.android.com/studio/index.html#command-tools)
- [frida](https://github.com/frida/frida)

### Useful References / Docs
- [project-layout](https://github.com/golang-standards/project-layout)
- [fmt docs](https://golang.org/pkg/fmt/)
- [testing docs](https://golang.org/pkg/testing/)
- [general coding docs](https://golang.org/doc/code.html)
- [gobyexample](https://gobyexample.com/)
- [r2pipe-go docs](https://godoc.org/github.com/radare/r2pipe-go)
- [go-yara docs](https://godoc.org/github.com/hillu/go-yara)
- [installing yara](https://yara.readthedocs.io/en/stable/gettingstarted.html)
- [frida API docs](https://frida.re/docs/javascript-api/)

### License
[GNU General Public License v3.0](https://github.com/arbitraryrw/MobProtID/blob/master/LICENSE)