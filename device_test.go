package deviceBinder

import (
	"fmt"
	"testing"
)

func TestGetUserDevice(t *testing.T) {
	uuid, err := getDeviceUUID()
	fmt.Println(uuid, err)
}
