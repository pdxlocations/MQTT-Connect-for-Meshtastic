Meshtastic MQTT Connect by pdxlocations

<img width="1110" alt="topology" src="https://github.com/pdxlocations/Meshtastic-MQTT-Connect/assets/117498748/a0bf657d-2f91-4b7e-8f77-95cecb621153">


Many thanks to and inspiration from: https://github.com/arankwende/meshtastic-mqtt-client & https://github.com/joshpirihi/meshtastic-mqtt

Requires packages: Meshtastic, Paho-MQTT, Tkinter, cryptography which might be installed with:

`pip3 install meshtastic paho-mqtt tk cryptography`

*** Mac OS Sonoma (and maybe others) ***
There is an upstream bug in Tkinter where mouse clicks in the UI are not registered, unless the mouse is in motion.
The current workaround is to move the application window away from it's opening state, and/or move the mouse slightly while clicking.
This is a bug with TCL Version 8.6.12 and is apparently fixed in 8.6.13

- Decryption is supported
- Encryption is not currently supported

<img width="1318" alt="Screenshot 2023-12-30 at 10 53 03 AM" src="https://github.com/pdxlocations/Meshtastic-MQTT-Connect/assets/117498748/1914d86d-39e7-46de-99e5-038fdbf4e54c">

![Alt](https://repobeats.axiom.co/api/embed/dbe69ee806d8db9d81e8342b70ef83fe1df87b8e.svg "Repobeats analytics image")
