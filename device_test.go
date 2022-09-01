package deviceBinder

import (
	"fmt"
	"testing"
)

func TestGetUserDevice(t *testing.T) {
	uuid, err := GetDeviceUUID()
	fmt.Println(uuid, err)
}
