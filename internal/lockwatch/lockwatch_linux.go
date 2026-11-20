//go:build linux

package lockwatch

import (
	"context"

	"github.com/godbus/dbus/v5"
)

func watch(ctx context.Context) (<-chan string, error) {
	return watchBus(ctx, func() (busConn, error) { return asBus(dbus.SystemBus()) })
}
