#!/usr/bin/env python3
"""
MQTT Connect for Meshtastic Version 0.8.6 by https://github.com/pdxlocations

Many thanks to and protos code from: https://github.com/arankwende/meshtastic-mqtt-client & https://github.com/joshpirihi/meshtastic-mqtt
Encryption/Decryption help from: https://github.com/dstewartgo

Powered by Meshtastic™ https://meshtastic.org/
"""

#### Imports

import random
import threading
import sqlite3
import time

import sys
from time import mktime

import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import tkinter.messagebox

import paho.mqtt.client as mqtt

from rx_message_handler import on_message
from helper_functions import sanitize_string, current_time, format_time, is_valid_hex, generate_hash
from encryption import encrypt_message, decode_encrypted
from preferences import debug, display_dm_emoji, dm_emoji, display_private_dms, encrypted_emoji, display_encrypted_emoji, auto_reconnect, auto_reconnect_delay
import preferences
from gui import build_gui
from mqtt_server import on_connect, on_disconnect



def mqtt_thread():
    """Function to run the MQTT client loop in a separate thread."""
    if debug:
        print("MQTT Thread")
        if client.is_connected():
            print("client connected")
        else:
            print("client not connected")
    while True:
        client.loop()


def send_node_info_periodically() -> None:
    """Function to broadcast NodeInfo in a separate thread."""
    while True:
        if client.is_connected():
            send_node_info(BROADCAST_NUM, want_response=False)

            if lon_entry.get() and lon_entry.get():
                send_position(BROADCAST_NUM)

        time.sleep(preferences.node_info_interval_minutes * 60)  # Convert minutes to seconds


def on_exit():
    """Function to be called when the GUI is closed."""
    if client.is_connected():
        client.disconnect()
        print("client disconnected")
    root.destroy()
    client.loop_stop()



### tcl upstream bug warning
tcl = tk.Tcl()
if sys.platform.startswith('darwin'):
    print(f"\n\n**** IF MAC OS SONOMA **** you are using tcl version: {tcl.call('info', 'patchlevel')}")
    print("If < version 8.6.13, mouse clicks will only be recognized when the mouse is moving")
    print("unless the window is moved from it's original position.")
    print("The built in window auto-centering code may help with this\n\n")

# Generate 4 random hexadecimal characters to create a unique node name
random_hex_chars = ''.join(random.choices('0123456789abcdef', k=4))
node_name = '!abcd' + random_hex_chars
if not is_valid_hex(node_name, 8, 8):
    print('Invalid generated node name: ' + str(node_name))
    sys.exit(1)

global_message_id = random.getrandbits(32)

# Convert hex to int and remove '!'
node_number = int(node_name.replace("!", ""), 16)

# Initialize presets from the file
presets = load_presets_from_file()


build_gui()


############################
# Main Threads

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="", clean_session=True, userdata=None)
client.on_connect = on_connect
client.on_disconnect = on_disconnect
client.on_message = on_message

def check_client_connected() -> bool:
    if not client.is_connected():
        return False
    return True


mqtt_thread = threading.Thread(target=mqtt_thread, daemon=True)
mqtt_thread.start()

node_info_timer = threading.Thread(target=send_node_info_periodically, daemon=True)
node_info_timer.start()


# Set the exit handler
root.protocol("WM_DELETE_WINDOW", on_exit)



# Start the main loop
root.mainloop()
