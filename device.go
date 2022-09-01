package deviceBinder

import (
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
)

func GetDeviceUUID() (uuid string, err error) {
	osname := runtime.GOOS
	var out []byte
	if osname == "windows" {
		out, err = exec.Command("wmic", "csproduct", "get", "UUID").Output()
	} else {
		out, err = exec.Command("dmidecode", "-s", "system-uuid").Output()
	}
	if err != nil {
		return "", err
	}
	if uuid, ok := isValidUUID(string(out)); ok {
		return uuid, nil
	} else {
		return "", fmt.Errorf("can't get uuid")
	}
}

func isValidUUID(idstring string) (uuid string, ok bool) {
	r := regexp.MustCompile("[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}")
	return r.FindString(idstring), r.MatchString(idstring)
}
