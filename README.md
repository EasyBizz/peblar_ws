# Peblar WS (Coolblue / BlueBuilt)

Home Assistant custom integration for Peblar-based EV chargers  
(OEM: Coolblue / BlueBuilt)

## Features
- Live WebSocket updates
- Charging state
- Instantaneous power
- Total energy
- WiFi RSSI
- LTE carrier information

## Installation (HACS)
1. Add this repository as a **custom repository** in HACS
2. Category: **Integration**
3. Install and restart Home Assistant
4. Add integration via **Settings → Devices & Services**

## Installation (Manual)
Copy `custom_components/peblar_ws` to: config/custom_components/

## Configuration
The Charger needs to be connected to the local network.
See the sticker on the back of the blue built booklet and "Enable WLAN Client" in the web interface, connect it to your local WiFi.

ATTENTION! DO NOT disable "WLAN hotspot" or you will not be able to get back in when your network is out.

You will need:
- Charger IP address (Local)
- Web UI username (not required)
- Web UI password

## Notes
- Uses authenticated WebSocket (same as web UI)
- No cloud dependency
- Tested on Coolblue / BlueBuilt firmware `1.4.4+COOLBLUE`

## Disclaimer
This project is not affiliated with Peblar or Coolblue.