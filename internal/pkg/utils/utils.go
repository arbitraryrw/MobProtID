package utils

import (
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var AnalysisDir string

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

	targetFileName := filepath.Base(targetAppPath)
	t := time.Now()
	analysisRootDir := "/tmp/mobprotid"
	formattedTime := t.Format("150405-02-01-2006")

	AnalysisDir = filepath.Join(analysisRootDir, targetFileName+"--"+formattedTime)

	if _, err := os.Stat(analysisRootDir); os.IsNotExist(err) {
		// os.Mkdir(path, mode)
		fmt.Println("it does not exist!!")
	}

}
