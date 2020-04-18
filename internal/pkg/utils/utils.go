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

// RetryR2Command is used to retry functions that may fail outside of the app's control
func RetryR2Command(attempts int, sleep time.Duration, f func() (interface{}, error)) (err error) {
	for i := 0; ; i++ {

		var res interface{}

		res, err = f()

		switch resType := res.(type) {
		default:
			fmt.Println("Unknown type: ", resType)
		case []interface{}:
			if len(res.([]interface{})) < 1 {
				fmt.Println("aaaaaaaaaaaaaaa", res)
			}
		case map[string]interface{}:
			if len(res.(map[string]interface{})) < 1 {
				fmt.Println("bbbbbbbbbbbb", res)
			}
		}

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
