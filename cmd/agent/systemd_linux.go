package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/godbus/dbus/v5"
)

// Approved dbus boundary: only the fixed local system-bus socket and EXTERNAL
// authentication are used. No environment address, session autolaunch, TCP,
// nonce-file or cookie path is reachable because the address is a constant and
// only the unix transport is requested. Calls are limited to the four systemd
// manager methods below on compiled unit names.
const systemBusAddress = "unix:path=/run/dbus/system_bus_socket"

const systemdDest = "org.freedesktop.systemd1"

type systemdManager struct {
	conn *dbus.Conn
	obj  dbus.BusObject
}

func connectSystemd() (*systemdManager, error) {
	if _, err := secureMutationPath("run/dbus/system_bus_socket", false); err != nil {
		return nil, errors.New("system bus socket is unavailable or not root-controlled")
	}
	conn, err := dbus.Dial(systemBusAddress)
	if err != nil {
		return nil, errors.New("cannot reach the local system bus")
	}
	if err = conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Geteuid()))}); err == nil {
		err = conn.Hello()
	}
	if err != nil {
		conn.Close()
		return nil, errors.New("system bus authentication failed")
	}
	return &systemdManager{conn, conn.Object(systemdDest, "/org/freedesktop/systemd1")}, nil
}

func (m *systemdManager) close() { m.conn.Close() }

func (m *systemdManager) call(method string, args ...any) *dbus.Call {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return m.obj.CallWithContext(ctx, "org.freedesktop.systemd1.Manager."+method, 0, args...)
}

// activeState returns "inactive" for units systemd has not loaded.
func (m *systemdManager) activeState(unit string) (string, error) {
	var path dbus.ObjectPath
	if err := m.call("GetUnit", unit).Store(&path); err != nil {
		var dbusErr dbus.Error
		if errors.As(err, &dbusErr) && dbusErr.Name == "org.freedesktop.systemd1.NoSuchUnit" {
			return "inactive", nil
		}
		return "", errors.New("cannot query unit state")
	}
	value, err := m.conn.Object(systemdDest, path).GetProperty("org.freedesktop.systemd1.Unit.ActiveState")
	state, ok := value.Value().(string)
	if err != nil || !ok {
		return "", errors.New("cannot read unit active state")
	}
	return state, nil
}

func (m *systemdManager) reload() error {
	if err := m.call("Reload").Err; err != nil {
		return errors.New("systemd daemon-reload failed")
	}
	return nil
}

// settle waits until a unit reaches a terminal state in want ("inactive" or "active").
func (m *systemdManager) settle(unit, want string) error {
	for i := 0; i < 30; i++ {
		state, err := m.activeState(unit)
		if err != nil {
			return err
		}
		if state == want {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("unit did not reach the expected state in time")
}

func (m *systemdManager) stop(unit string) error {
	var job dbus.ObjectPath
	if err := m.call("StopUnit", unit, "replace").Store(&job); err != nil {
		return errors.New("systemd refused to stop the unit")
	}
	return m.settle(unit, "inactive")
}

func (m *systemdManager) start(unit string) error {
	var job dbus.ObjectPath
	if err := m.call("StartUnit", unit, "replace").Store(&job); err != nil {
		return errors.New("systemd refused to start the unit")
	}
	return m.settle(unit, "active")
}
