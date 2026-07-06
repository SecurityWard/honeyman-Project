#!/usr/bin/env bash
# Honeyman WiFi adapter inventory.
#
# Prints every WiFi interface with its driver, MAC, current mode, and
# whether it can do monitor mode — plus which interface carries the
# default route. Use it to decide which adapter stays on the internet
# (the internal radio) and which one is dedicated to WiFi monitoring
# (a second, external USB adapter).
#
# Read-only: it changes nothing. Run it with:
#     curl -sSL https://honeymanproject.com/wifi-check | bash

set -u

echo "################ Honeyman WiFi adapter inventory ################"

found=0
for path in /sys/class/net/wl*; do
    [ -e "$path" ] || continue
    found=1
    i="${path##*/}"
    mac="$(cat "$path/address" 2>/dev/null)"
    drv="$(basename "$(readlink "$path/device/driver" 2>/dev/null)" 2>/dev/null)"
    [ -z "$drv" ] && drv="unknown"

    echo
    echo "=== $i ==="
    echo "  mac:     $mac"
    echo "  driver:  $drv"

    # brcmfmac is the Broadcom radio built into the Pi. Anything else is
    # (almost certainly) the external USB adapter.
    if [ "$drv" = "brcmfmac" ]; then
        echo "  role:    INTERNAL  -> keep this one on the internet"
    else
        echo "  role:    EXTERNAL  -> candidate for monitor mode"
    fi

    # Current operating mode (managed / monitor).
    mode="$(iw dev "$i" info 2>/dev/null | awk '/type/{print $2}')"
    echo "  mode:    ${mode:-unknown}"

    # Can this adapter do monitor mode at all? Some cheap USB dongles can't.
    phy="$(iw dev "$i" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')"
    if [ -n "$phy" ] && iw phy "$phy" info 2>/dev/null | grep -q '\* monitor'; then
        echo "  monitor: SUPPORTED"
    else
        echo "  monitor: NOT supported (can't be used for WiFi detection)"
    fi
done

if [ "$found" -eq 0 ]; then
    echo
    echo "No WiFi interfaces (wl*) found."
fi

echo
echo "=== default route (this interface must stay on the internet) ==="
ip route show default || echo "  (no default route — you have no internet right now)"
echo
echo "################################################################"
echo "Next: tell Honeyman which one is EXTERNAL. The internal (brcmfmac)"
echo "adapter keeps the internet; the external one goes into monitor mode."
echo "################################################################"
