package utils

import (
	"strconv"
	"testing"
)

func TestGetDroidManifest(t *testing.T) {

	got := GetDroidManifest("../../../test/dummy_app_MobProtID.apk")

	if val, ok := got["allowBackup"]; ok {

		expect := true
		allowBackup, _ := strconv.ParseBool(val)

		if expect != allowBackup {
			t.Errorf("TestGetDroidManifest() = expected allowBackup to be %v, got %v", expect, allowBackup)
		}

	} else {
		t.Errorf("TestGetDroidManifest() = could not find allowBackup key, recieved: %q", got)
	}

	if val, ok := got["debuggable"]; ok {

		expect := true
		debuggable, _ := strconv.ParseBool(val)

		if expect != debuggable {
			t.Errorf("TestGetDroidManifest() = expected debuggable to be %v, got %v", expect, debuggable)
		}

	} else {
		t.Errorf("TestGetDroidManifest() = could not find debuggable key, recieved: %q", got)
	}

	if val, ok := got["minSdkVersion"]; ok {

		expect := "25"

		if expect != val {
			t.Errorf("TestGetDroidManifest() = expected minSdkVersion to be %q, got %q", expect, val)
		}

	} else {
		t.Errorf("TestGetDroidManifest() = could not find minSdkVersion key, recieved: %q", got)
	}

	if val, ok := got["targetSdkVersion"]; ok {

		expect := "29"

		if expect != val {
			t.Errorf("TestGetDroidManifest() = expected targetSdkVersion to be %q, got %q", expect, val)
		}

	} else {
		t.Errorf("TestGetDroidManifest() = could not find targetSdkVersion key, recieved: %q", got)
	}

	if val, ok := got["package"]; ok {

		expect := "com.example.dummyapplication"

		if expect != val {
			t.Errorf("TestGetDroidManifest() = expected package to be %q, got %q", expect, val)
		}

	} else {
		t.Errorf("TestGetDroidManifest() = could not find package key, recieved: %q", got)
	}

}
