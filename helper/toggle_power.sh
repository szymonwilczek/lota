#!/bin/bash

# Usage: ./toggle_power.sh [ON|OFF]

if [ "$EUID" -ne 0 ]; then
  exec sudo "$0" "$@"
fi

PID_FILE="/run/syz-inhibit.pid"

# real user who invoked sudo (for GNOME settings)
REAL_USER="${SUDO_USER:-$LOGNAME}"
if [ "$REAL_USER" == "root" ]; then
    REAL_USER=$(getent passwd "1000" | cut -d: -f1)
fi

function set_gnome_idle() {
    local enable_idle=$1 # 0=disable, 1=enable
    local user=$2
    
    if [ -z "$user" ] || [ "$user" == "root" ]; then return; fi
    
    USER_ID=$(id -u "$user")
    local bus_addr="unix:path=/run/user/$USER_ID/bus"
    
    if [ "$enable_idle" -eq 0 ]; then
        echo "-> Disabling GNOME idle-delay for user $user..."
        sudo -u "$user" DBUS_SESSION_BUS_ADDRESS="$bus_addr" gsettings set org.gnome.desktop.session idle-delay 0
        sudo -u "$user" DBUS_SESSION_BUS_ADDRESS="$bus_addr" gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 'nothing'
    else
        echo "-> Restoring GNOME idle-delay for user $user..."
        sudo -u "$user" DBUS_SESSION_BUS_ADDRESS="$bus_addr" gsettings set org.gnome.desktop.session idle-delay 300
        sudo -u "$user" DBUS_SESSION_BUS_ADDRESS="$bus_addr" gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 'suspend'
    fi
}

if [ "$1" == "ON" ]; then
    if [ -f "$PID_FILE" ] && ps -p $(cat "$PID_FILE") > /dev/null; then
        echo "ALREADY ON (PID: $(cat $PID_FILE))."
        exit 0
    fi
    
    echo "=== Enabling Keep-Awake Mode (Runtime Lock) ==="
    
    nohup systemd-inhibit \
        --what="handle-lid-switch:idle:sleep" \
        --who="SyzkallerUser" \
        --why="Fuzzing Session" \
        --mode=block \
        sleep infinity >/dev/null 2>&1 &
    
    rm -f "$PID_FILE"
    echo $! > "$PID_FILE"
    echo "-> Power inhibitor started (PID: $!). Laptop will NOT sleep."
    
    set_gnome_idle 0 "$REAL_USER"
    
    echo "DONE."

elif [ "$1" == "OFF" ]; then
    echo "=== Disabling Keep-Awake Mode ==="
    
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null; then
            echo "-> Stopping power inhibitor (PID: $PID)..."
            kill "$PID"
        fi
        rm -f "$PID_FILE"
    else
        echo "-> Inhibitor not running."
    fi
    
    set_gnome_idle 1 "$REAL_USER"
    
    echo "DONE. System defaults active."

else
    echo "Usage: ./toggle_power.sh [ON|OFF]"
    exit 1
fi
