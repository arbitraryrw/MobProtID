package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var AnalysisDir string
var AnalysisBinPath string

const analysisRootDir string = "/tmp/mobprotid"

//Description Dummy function to check scope
func Description() string {
	return "utils coming in!"
}

//GetProjectRootDir returns the project root dir of MobProtID
func GetProjectRootDir() string {
	var _, b, _, _ = runtime.Caller(0)
	var basePath = filepath.Dir(b)
	splitPath := strings.Split(basePath, string(os.PathSeparator))

	rulePath := "/"

	for _, dir := range splitPath {

		rulePath = path.Join(rulePath, dir)

		if dir == "MobProtID" {
			break
		}
	}

	return rulePath
}

// GetWorkingDir - More info on Getwd()
// https://golang.org/src/os/getwd.go
func GetWorkingDir() string {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	return dir
}

// Retry is used to retry functions that may fail outside of the app's control
func Retry(attempts int, sleep time.Duration, f func() error) (err error) {
	for i := 0; ; i++ {

		err = f()

		if err == nil {
			return
		}

		if i >= (attempts - 1) {
			break
		}

		time.Sleep(sleep)

		log.Println("retrying after error:", err)
	}
	return fmt.Errorf("after %d attempts, last error: %s", attempts, err)
}

func CreateAnalysisDir(targetAppPath string) {

	cleanupAnalysisDir()

	targetFileName := filepath.Base(targetAppPath)
	t := time.Now()
	formattedTime := t.Format("150405-02-01-2006")

	AnalysisDir = filepath.Join(analysisRootDir, targetFileName+"--"+formattedTime)

	if _, err := os.Stat(analysisRootDir); os.IsNotExist(err) {
		os.Mkdir(analysisRootDir, os.ModePerm)
	}

	if _, err := os.Stat(AnalysisDir); os.IsNotExist(err) {
		os.Mkdir(AnalysisDir, os.ModePerm)
	}
}

func cleanupAnalysisDir() {

	if _, err := os.Stat(analysisRootDir); err == nil {
		os.RemoveAll(analysisRootDir + "/")
	}

}

func PrepBinaryForAnal(path string) {

	fmt.Println("[INFO] Prepping binary for anal")

	fn := filepath.Base(path)

	AnalysisBinPath = filepath.Join(AnalysisDir, fn)

	err := CopyFile(path, AnalysisBinPath)

	if err != nil {
		fmt.Println("[ERROR]Failed to copy files:", err)
	}

}

func CopyFile(src, dst string) (err error) {
	sfi, err := os.Stat(src)
	if err != nil {
		fmt.Println("os.stat error")
		return
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (directories / symlinks etc)
		return fmt.Errorf("CopyFile: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}

	// Check the stat of the file
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("CopyFile: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			fmt.Println("[INFO] File already exists at directory, no need to copy")
			return
		}
	}
	err = copyFileContents(src, dst)
	return
}

func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}
