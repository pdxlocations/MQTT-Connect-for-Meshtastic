## Connect - An nodeless MQTT Client for Meshtastic

<img width="1110" alt="topology" src="https://github.com/pdxlocations/Meshtastic-MQTT-Connect/assets/117498748/a0bf657d-2f91-4b7e-8f77-95cecb621153">


Many thanks to and inspiration from:<br>
 https://github.com/arankwende/meshtastic-mqtt-client & https://github.com/joshpirihi/meshtastic-mqtt<br>
<b>Powered by Meshtastic.org</b>

### Installation

```bash
python3 -m venv connect
cd connect && source bin/activate
pip3 install meshtastic paho-mqtt tk cryptography
git clone https://github.com/pdxlocations/MQTT-Connect-for-Meshtastic
cd MQTT-Connect-for-Meshtastic
```

### Running the Client
```bash
python mqtt-connect.py
```

*** Mac OS Sonoma (and maybe others) ***
There is an upstream bug in Tkinter where mouse clicks in the UI are not registered, unless the mouse is in motion.
The current workaround is to move the application window away from it's opening state, and/or move the mouse slightly while clicking.
This is a bug with TCL Version 8.6.12 and is apparently fixed in 8.6.13


<img width="1113" alt="Screenshot 2024-02-16 at 2 46 56 PM" src="https://github.com/pdxlocations/Meshtastic-MQTT-Connect/assets/117498748/a7322f8d-0a31-4864-a558-aab725c5f92e">

### TLS 

TLS is supported by entering a broker ending in `:8883` You will need to install a valid cacert.pem file.

In the directory in which you run Meshtastic-MQTT-Connect run the following commands once:
```sh
pip3 install certifi
ln -s `python3 -c 'import certifi ; print(certifi.where())'` cacert.pem
```

### Interactive Map
To view the interactive map you may need to install folium with

`pip install folium`

In meshtastic-mqtt-connect.py set `record_locations = True` in the configuration options around line 44.

After you've connected to a channel for some time and received location information from at least one station, open mmc-map.py and enter your channel name.

Run mmc-map.py and a file will be generated called mmc-map.html which may be opened in a browser.

<img width="964" alt="Screenshot 2024-01-10 at 11 12 37 PM" src="https://github.com/pdxlocations/Meshtastic-MQTT-Connect/assets/117498748/2ab888bb-ac0b-448a-bd23-4648345de3a8">



![Alt](https://repobeats.axiom.co/api/embed/dbe69ee806d8db9d81e8342b70ef83fe1df87b8e.svg "Repobeats analytics image")
