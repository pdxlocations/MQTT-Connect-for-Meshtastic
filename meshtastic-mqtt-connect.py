#!/usr/bin/env python3
'''
Meshtastic MQTT Connect Version 0.1.5 by https://github.com/pdxlocations

Many thanks to and protos code from: https://github.com/arankwende/meshtastic-mqtt-client & https://github.com/joshpirihi/meshtastic-mqtt
Decryption help from dstewartgo
''' 

import tkinter as tk
from tkinter import scrolledtext, simpledialog
import paho.mqtt.client as mqtt
from meshtastic import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2
import random
import threading
import sqlite3
import time
import tkinter.messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import base64
import json


debug = True

tcl = tk.Tcl()
print(f"\n\n**** IF MAC OS SONOMA **** you are using tcl version: {tcl.call('info', 'patchlevel')}")
print("If < version 8.6.13, mouse clicks will only be recognized when the mouse is moving")    
print("unless the window is moved from it's original position.")    
print("The built in window auto-centering code may help with this\n\n")      

### Default settings
mqtt_broker = "mqtt.meshtastic.org"
mqtt_port = 1883
mqtt_username = "meshdev"
mqtt_password = "large4cats"

channel = "LongFast"
key = "AQ=="
# 
# node_number = 3126770193
node_number = 2900000000 + random.randint(0,99999)

node_name = '!' + hex(node_number)[2:]
client_short_name = "MMC"
client_long_name = "MQTTastic"
client_hw_model = 255
node_info_interval_minutes = 15

### Program variables
default_key = bytes([0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01]) # AQ==
broadcast_id = 4294967295
last_received_message = None
db_file_path = "nodeinfo_"+ mqtt_broker + "_" + channel + ".db"
PRESETS_FILE = "presets.json"


class Preset:
    def __init__(self, name, broker, username, password, channel, key, node_number, long_name, short_name):
        self.name = name
        self.broker = broker
        self.username = username
        self.password = password
        self.channel = channel
        self.key = key
        self.node_number = node_number
        self.long_name = long_name
        self.short_name = short_name

    def to_dict(self):
        return {
            'name': self.name,
            'broker': self.broker,
            'username': self.username,
            'password': self.password,
            'channel': self.channel,
            'key': self.key,
            'node_number': self.node_number,
            'long_name': self.long_name,
            'short_name': self.short_name
        }
    
presets = {}
# presets["Default"] = Preset("Default", "mqtt.meshtastic.org", "meshdev", "large4cats", "LongFast", "AQ==", 3126770193, "MQTTastic", "MMC")

def save_preset():
    if debug: print("save_preset")
    name = tkinter.simpledialog.askstring("Save Preset", "Enter preset name:")
        # Check if the user clicked Cancel
    if name is None:
        return

    preset = Preset(name, mqtt_broker_entry.get(), mqtt_username_entry.get(), mqtt_password_entry.get(),
                    channel_entry.get(), key_entry.get(), node_number_entry.get(),
                    long_name_entry.get(), short_name_entry.get())
    presets[name] = preset  # Store the Preset object directly
    update_preset_dropdown()
    preset_var.set(name) 
    save_presets_to_file()

# Function to load the selected preset
def load_preset():
    if debug: print("load_preset")
    selected_preset_name = preset_var.get()
    
    if selected_preset_name in presets:
        selected_preset = presets[selected_preset_name]
        if debug: print(f"Loading preset: {selected_preset_name}")
        
        mqtt_broker_entry.delete(0, tk.END)
        mqtt_broker_entry.insert(0, selected_preset.broker)
        mqtt_username_entry.delete(0, tk.END)
        mqtt_username_entry.insert(0, selected_preset.username)
        mqtt_password_entry.delete(0, tk.END)
        mqtt_password_entry.insert(0, selected_preset.password)
        channel_entry.delete(0, tk.END)
        channel_entry.insert(0, selected_preset.channel)
        key_entry.delete(0, tk.END)
        key_entry.insert(0, selected_preset.key)
        node_number_entry.delete(0, tk.END)
        node_number_entry.insert(0, selected_preset.node_number)
        long_name_entry.delete(0, tk.END)
        long_name_entry.insert(0, selected_preset.long_name)
        short_name_entry.delete(0, tk.END)
        short_name_entry.insert(0, selected_preset.short_name)

    else:
        print(f"Error: Preset '{selected_preset_name}' not found.")
    

    
def update_preset_dropdown():
    # Update the preset dropdown menu
    preset_names = list(presets.keys())
    menu = preset_dropdown['menu']
    menu.delete(0, 'end')
    for preset_name in preset_names:
        menu.add_command(label=preset_name, command=tk._setit(preset_var, preset_name, lambda *args: load_preset()))





def preset_var_changed(*args):
    selected_option = preset_var.get()
    update_preset_dropdown()
    print(f"Selected Option: {selected_option}")




# Function to save the presets to a file
# Function to save the presets to a file
def save_presets_to_file():
    if debug: print("save_presets_to_file")

    with open(PRESETS_FILE, "w") as file:
        json.dump({name: preset.__dict__ for name, preset in presets.items()}, file, indent=2)

# Function to load presets from a file
def load_presets_from_file():
    if debug: print("load_presets_from_file")
    try:
        with open(PRESETS_FILE, "r") as file:
            loaded_presets = json.load(file)
            return {name: Preset(**data) for name, data in loaded_presets.items()}
    except FileNotFoundError:
        return {}
# Initialize presets from the file
presets = load_presets_from_file()


def set_topic():
    global subscribe_topic, publish_topic, node_number, node_name
    node_name = '!' + hex(node_number)[2:]
    subscribe_topic = "msh/2/c/" + channel + "/#"
    publish_topic = "msh/2/c/" + channel + "/" + node_name


### Create database table for NodeDB
def setup_db():
    if debug: print("setup_db")
    global db_connection
    db_connection = sqlite3.connect(db_file_path)
    db_cursor = db_connection.cursor()

    # Create a table if it doesn't exist
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS nodeinfo (
            user_id TEXT,
            long_name TEXT,
            short_name TEXT
        )
    ''')

    # Create a new table for storing messages
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            timestamp TEXT,
            sender TEXT,
            content TEXT,
            message_id TEXT        
        )
    ''')

    db_connection.commit()
    db_connection.close()

### Called when a new message is received on the MQTT topic
def on_message(client, userdata, msg):
    # if debug: print("on_message")
    se = mqtt_pb2.ServiceEnvelope()
    # print (f"message: {msg}")
    se.ParseFromString(msg.payload)
    mp = se.packet

    if mp.HasField("encrypted") and not mp.HasField("decoded"):
        try:
            # Convert key to bytes
            key_bytes = base64.b64decode(key.encode('ascii'))

            nonce_packet_id = getattr(mp, "id").to_bytes(8, "little")
            nonce_from_node = getattr(mp, "from").to_bytes(8, "little")

            # Put both parts into a single byte array.
            nonce = nonce_packet_id + nonce_from_node

            # decrypt_cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce)
            if key == "AQ==":
                key_bytes = default_key


            cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_bytes = decryptor.update(getattr(mp, "encrypted")) + decryptor.finalize()


            # plain_text = decrypted_bytes.decrypt(getattr(mp, "encrypted"))
            data = mesh_pb2.Data()
            data.ParseFromString(decrypted_bytes)
            mp.decoded.CopyFrom(data)

        except Exception as e:
            print(f"*** Decryption failed: {str(e)}")
            return


    if mp.decoded.portnum == portnums_pb2.TEXT_MESSAGE_APP:
        text_payload = mp.decoded.payload.decode("utf-8")
        process_message(mp, text_payload)
        # print(f"{text_payload}")
        

    elif mp.decoded.portnum == portnums_pb2.NODEINFO_APP:
        info = mesh_pb2.User()
        info.ParseFromString(mp.decoded.payload)
        maybe_store_nodeinfo_in_db(info)
        # print(info)
        
    # elif mp.decoded.portnum == portnums_pb2.POSITION_APP:
    #     pos = mesh_pb2.Position()
    #     pos.ParseFromString(mp.decoded.payload)
    #     print(getattr(mp, "from"))
    #     print(pos)

    # elif mp.decoded.portnum == portnums_pb2.TELEMETRY_APP:
    #     env = telemetry_pb2.EnvironmentMetrics()
    #     env.ParseFromString(mp.decoded.payload)
    #     print (f"{env.temperature}, {env.relative_humidity}")
    #     print(env)

def current_time():
    current_time_seconds = time.time()
    current_time_struct = time.localtime(current_time_seconds)
    current_time_str = time.strftime("%H:%M:%S", current_time_struct)
    return(current_time_str)

def process_message(mp, text_payload):
    print("packet received")
    global last_received_message

    if text_payload != last_received_message:
        sender_short_name = get_short_name_by_id(getattr(mp, "from"))
        if getattr(mp, "to") == node_number:
            string = f"{current_time()} DM from {sender_short_name}: {text_payload}"
        elif getattr(mp, "from") == node_number and getattr(mp, "to") != broadcast_id:
            receiver_short_name = get_short_name_by_id(getattr(mp, "to"))
            string = f"{current_time()} DM to {receiver_short_name}: {text_payload}"
        else:    
            string = f"{current_time()} {sender_short_name}: {text_payload}"

        update_gui(string, message_history)
        m_id = getattr(mp, "id")
        insert_message_to_db(current_time(), sender_short_name, text_payload, m_id)

        last_received_message = text_payload
        text = {
            "message": text_payload,
            "from": getattr(mp, "from"),
            "id": getattr(mp, "id"),
            "to": getattr(mp, "to")
        }
        print(text)


def get_short_name_by_id(user_id):
    try:
        db_connection = sqlite3.connect(db_file_path)
        db_cursor = db_connection.cursor()
        
        # Convert the user_id to hex and prepend '!'
        hex_user_id = '!' + hex(user_id)[2:]

        # Fetch the short name based on the hex user ID
        result = db_cursor.execute('SELECT short_name FROM nodeinfo WHERE user_id=?', (hex_user_id,)).fetchone()

        if result:
            return result[0]
        else:
            return f"Unknown User ({hex_user_id})"
    
    except sqlite3.Error as e:
        print(f"SQLite error in get_short_name_by_id: {e}")
    
    finally:
        db_connection.close()


def direct_message(destination_id):
    if debug: print("direct_message")
    destination_id = int(destination_id[1:], 16)
    publish_message(destination_id)


def publish_message(destination_id):
    if debug: print("publish_message")

    if not client.is_connected():
        connect_mqtt()

    message_text = message_entry.get()
    if message_text:
        encoded_message = mesh_pb2.Data()
        encoded_message.portnum = portnums_pb2.TEXT_MESSAGE_APP 
        encoded_message.payload = message_text.encode("utf-8")

        mesh_packet = mesh_pb2.MeshPacket()
        mesh_packet.decoded.CopyFrom(encoded_message)

        setattr(mesh_packet, "from", node_number)
        mesh_packet.id = random.getrandbits(32)
        mesh_packet.to = destination_id
        mesh_packet.want_ack = True
        # mesh_packet.want_ack = False
        mesh_packet.channel = 0
        mesh_packet.hop_limit = 3

        service_envelope = mqtt_pb2.ServiceEnvelope()
        service_envelope.packet.CopyFrom(mesh_packet)
        service_envelope.channel_id = channel
        service_envelope.gateway_id = node_name

        # print (service_envelope)
        payload = service_envelope.SerializeToString()
        set_topic()
        if debug: print(f"Publish Topic is: {publish_topic}")
        client.publish(publish_topic, payload)
        message_entry.delete(0, tk.END)


def send_node_info():
    if debug: print("send_node_info")
    message =  current_time() + " >>> Sending NodeInfo Packet"
    update_gui(message)

    global client_short_name, client_long_name, node_name, node_number, client_hw_model, broadcast_id

    client_short_name = short_name_entry.get()
    client_long_name = long_name_entry.get()
    node_number = int(node_number_entry.get())

    decoded_client_id = bytes(node_name, "utf-8")
    decoded_client_long = bytes(client_long_name, "utf-8")
    decoded_client_short = bytes(client_short_name, "utf-8")
    decoded_client_hw_model = 255
    user_payload = mesh_pb2.User()
    setattr(user_payload, "id", decoded_client_id)
    setattr(user_payload, "long_name", decoded_client_long)
    setattr(user_payload, "short_name", decoded_client_short)
    setattr(user_payload, "hw_model", decoded_client_hw_model)

    user_payload = user_payload.SerializeToString()
    encoded_message = mesh_pb2.Data()
    encoded_message.portnum = portnums_pb2.NODEINFO_APP
    encoded_message.payload = user_payload

    mesh_packet = mesh_pb2.MeshPacket()
    mesh_packet.decoded.CopyFrom(encoded_message)

    setattr(mesh_packet, "from", node_number)
    mesh_packet.id = random.getrandbits(32)
    mesh_packet.to = broadcast_id
    mesh_packet.want_ack = True
    mesh_packet.channel = 0
    mesh_packet.hop_limit = 3

    service_envelope = mqtt_pb2.ServiceEnvelope()
    service_envelope.packet.CopyFrom(mesh_packet)
    service_envelope.channel_id = channel
    service_envelope.gateway_id = node_name
    # print (service_envelope)

    payload = service_envelope.SerializeToString()
    set_topic()
    client.publish(publish_topic, payload)


def maybe_store_nodeinfo_in_db(info):
    if debug: print("node info packet received: Checking for existing entry in DB")

    try:
        db_connection = sqlite3.connect(db_file_path)
        db_cursor = db_connection.cursor()
        
        # Check if a record with the same user_id already exists
        existing_record = db_cursor.execute('SELECT * FROM nodeinfo WHERE user_id=?', (info.id,)).fetchone()

        if existing_record is None:
            if debug: print("no record found, adding node to db")
            # No existing record, insert the new record
            db_cursor.execute('''
                INSERT INTO nodeinfo (user_id, long_name, short_name)
                VALUES (?, ?, ?)
            ''', (info.id, info.long_name, info.short_name))
            db_connection.commit()

            # Fetch the new record
            new_record = db_cursor.execute('SELECT * FROM nodeinfo WHERE user_id=?', (info.id,)).fetchone()

            # Display the new record in the nodeinfo_window widget
            message = f"{new_record[0]}, {new_record[1]}, {new_record[2]}"
            update_gui(message, text_widget=nodeinfo_window)

    except sqlite3.Error as e:
        print(f"SQLite error in maybe_store_nodeinfo_in_db: {e}")

    finally:
        db_connection.close()


def update_node_list():
    try:
        db_connection = sqlite3.connect(db_file_path)
        db_cursor = db_connection.cursor()

        # Fetch all nodes from the database
        nodes = db_cursor.execute('SELECT user_id, long_name, short_name FROM nodeinfo').fetchall()

        # Clear the display
        nodeinfo_window.config(state=tk.NORMAL)
        nodeinfo_window.delete('1.0', tk.END)

        # Display each node in the nodeinfo_window widget
        for node in nodes:
            message = f"{node[0]}, {node[1]}, {node[2]}\n"
            nodeinfo_window.insert(tk.END, message)

        nodeinfo_window.config(state=tk.DISABLED)

    except sqlite3.Error as e:
        print(f"SQLite error in update_node_list: {e}")

    finally:
        db_connection.close()


def insert_message_to_db(time, sender_short_name, text_payload, message_id):
    if debug: print("insert_message_to_db")
    try:
        db_connection = sqlite3.connect(db_file_path)
        db_cursor = db_connection.cursor()

        # Strip newline characters and insert the message into the messages table
        formatted_message = text_payload.strip()
        db_cursor.execute('INSERT INTO messages (timestamp, sender, content, message_id) VALUES (?,?,?,?)', (time, sender_short_name, formatted_message, message_id))
        db_connection.commit()

    except sqlite3.Error as e:
        print(f"SQLite error in insert_message_to_db: {e}")

    finally:
        db_connection.close()

def load_message_history_from_db():
    if debug: print("load_message_history_from_db")
    try:
        db_connection = sqlite3.connect(db_file_path)
        db_cursor = db_connection.cursor()

        # Fetch all messages from the database
        messages = db_cursor.execute('SELECT timestamp, sender, content FROM messages').fetchall()

        message_history.config(state=tk.NORMAL)
        message_history.delete('1.0', tk.END)

        # Display each message in the message_history widget
        for message in messages:
            the_message = f"{message[0]} {message[1]}: {message[2]}\n"
            message_history.insert(tk.END, the_message)

        message_history.config(state=tk.DISABLED)

    except sqlite3.Error as e:
        print(f"SQLite error in load_message_history_from_db: {e}")

    finally:
        db_connection.close()


def erase_nodedb():
    if debug: print("erase_nodedb")

    confirmed = tkinter.messagebox.askyesno("Confirmation", "Are you sure you want to erase the database: " + db_file_path + "?")

    if confirmed:
        db_connection = sqlite3.connect(db_file_path)
        db_cursor = db_connection.cursor()

        # Clear all records from the database
        db_cursor.execute('DELETE FROM nodeinfo')
        db_connection.commit()

        db_connection.close()

        # Clear the display
        nodeinfo_window.config(state=tk.NORMAL)
        nodeinfo_window.delete('1.0', tk.END)
        nodeinfo_window.config(state=tk.DISABLED)
        update_gui(current_time() + " >>> Node database erased successfully.")
    else:
        update_gui(current_time() + " >>> Node database erase cancelled.")

def erase_messagedb():
    if debug: print("erase_messagedb")

    confirmed = tkinter.messagebox.askyesno("Confirmation", "Are you sure you want to erase the message history of: " + db_file_path + "?")

    if confirmed:
        db_connection = sqlite3.connect(db_file_path)
        db_cursor = db_connection.cursor()

        # Clear all records from the database
        db_cursor.execute('DELETE FROM messages')
        db_connection.commit()

        db_connection.close()

        # Clear the display
        message_history.config(state=tk.NORMAL)
        message_history.delete('1.0', tk.END)
        message_history.config(state=tk.DISABLED)
        update_gui(current_time() + " >>> Message history erased successfully.")
    else:
        update_gui(current_time() + " >>> Message history erase cancelled.")


def update_gui(text_payload, text_widget=None):
    if debug: print(f"updating GUI with: {text_payload}")
    text_widget = text_widget or message_history
    text_widget.config(state=tk.NORMAL)
    text_widget.insert(tk.END, f"{text_payload}\n")
    text_widget.config(state=tk.DISABLED)
    text_widget.yview(tk.END)


def on_nodeinfo_enter(event):
    # Change the cursor to a pointer when hovering over text
    nodeinfo_window.config(cursor="cross")

def on_nodeinfo_leave(event):
    # Change the cursor back to the default when leaving the widget
    nodeinfo_window.config(cursor="")

def on_nodeinfo_click(event):
    if debug: print("on_nodeinfo_click")
    global to_id
    # Get the index of the clicked position
    index = nodeinfo_window.index(tk.CURRENT)

    # Extract the user_id from the clicked line
    clicked_line = nodeinfo_window.get(index + "linestart", index + "lineend")
    to_id = clicked_line.split(",")[0].strip()

    # Update the "to" variable with the clicked user_id
    entry_dm.delete(0, tk.END)
    entry_dm.insert(0, to_id)


def connect_mqtt():
    if debug: print("connect_mqtt")
    global mqtt_broker, mqtt_username, mqtt_password, channel, node_number, db_file_path, key
    if not client.is_connected():
        try:
            mqtt_broker = mqtt_broker_entry.get()
            mqtt_username = mqtt_username_entry.get()
            mqtt_password = mqtt_password_entry.get()
            channel = channel_entry.get()
            key = key_entry.get()
            node_number = int(node_number_entry.get())  # Convert the input to an integer

            padded_key = key.ljust(len(key) + ((4 - (len(key) % 4)) % 4), '=')
            print (padded_key)
            replaced_key = padded_key.replace('-', '+').replace('_', '/')
            key = replaced_key

            db_file_path = mqtt_broker + "_" + channel + ".db"
            setup_db()

            client.username_pw_set(mqtt_username, mqtt_password)
            client.connect(mqtt_broker, mqtt_port, 60)
            update_gui(f"{current_time()} >>> Connecting to MQTT broker at {mqtt_broker}...")

        except Exception as e:
            update_gui(f"{current_time()} >>> Failed to connect to MQTT broker: {str(e)}")

        update_node_list()
    else:
        update_gui(f"{current_time()} >>> Already connected to {mqtt_broker}")


def disconnect_mqtt():
    if debug: print("disconnect_mqtt")
    if client.is_connected():
        client.disconnect()
        update_gui(f"{current_time()} >>> Disconnected from MQTT broker")
        # Clear the display
        nodeinfo_window.config(state=tk.NORMAL)
        nodeinfo_window.delete('1.0', tk.END)
        nodeinfo_window.config(state=tk.DISABLED)
    else:
        update_gui("Already disconnected")


def on_connect(client, userdata, flags, rc):

    set_topic()
    
    if debug: print("on_connect")
    if debug: 
        if client.is_connected():
            print("client is connected")
    
    if rc == 0:
        load_message_history_from_db()
        if debug: print(f"Subscribe Topic is: {subscribe_topic}")
        client.subscribe(subscribe_topic)
        message = f"{current_time()} >>> Connected to {mqtt_broker} on topic {channel} as {'!' + hex(node_number)[2:]}"

        update_gui(message)
        send_node_info()

    else:
        message = f"{current_time()} >>> Failed to connect to MQTT broker with result code {str(rc)}"
        update_gui(message)
    

def on_disconnect(client, userdata, rc):
    if debug: print("on_disconnect")
    if rc != 0:
        message = f"{current_time()} >>> Disconnected from MQTT broker with result code {str(rc)}"
        update_gui(message)


############################
# GUI setup
        
root = tk.Tk()
root.title("Meshtastic MQTT Connect")
# root.geometry("1200x850")

root.grid_rowconfigure(9, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_columnconfigure(2, weight=1)
root.grid_columnconfigure(3, weight=10)


w = 1200 # ~width for the Tk root
h = 900 # ~height for the Tk root

ws = root.winfo_screenwidth() # width of the screen
hs = root.winfo_screenheight() # height of the screen
x = (ws/2) - (w/2)
y = (hs/2) - (h/2)

root.geometry("+%d+%d" %(x,y))
# root.resizable(0,0)

### SERVER SETTINGS
mqtt_broker_label = tk.Label(root, text="MQTT Broker:")
mqtt_broker_label.grid(row=0, column=0, padx=10, pady=1, sticky=tk.W)

mqtt_broker_entry = tk.Entry(root)
mqtt_broker_entry.grid(row=0, column=1, padx=10, pady=1, sticky=tk.EW)
mqtt_broker_entry.insert(0, mqtt_broker)


mqtt_username_label = tk.Label(root, text="MQTT Username:")
mqtt_username_label.grid(row=1, column=0, padx=10, pady=1, sticky=tk.W)

mqtt_username_entry = tk.Entry(root)
mqtt_username_entry.grid(row=1, column=1, padx=10, pady=1, sticky=tk.EW)
mqtt_username_entry.insert(0, mqtt_username)


mqtt_password_label = tk.Label(root, text="MQTT Password:")
mqtt_password_label.grid(row=2, column=0, padx=10, pady=1, sticky=tk.W)

mqtt_password_entry = tk.Entry(root, show="*")
mqtt_password_entry.grid(row=2, column=1, padx=10, pady=1, sticky=tk.EW)
mqtt_password_entry.insert(0, mqtt_password)


channel_label = tk.Label(root, text="Channel:")
channel_label.grid(row=3, column=0, padx=10, pady=1, sticky=tk.W)

channel_entry = tk.Entry(root)
channel_entry.grid(row=3, column=1, padx=10, pady=1, sticky=tk.EW)
channel_entry.insert(0, channel)


key_label = tk.Label(root, text="Key: (decrypt receive only)")
key_label.grid(row=4, column=0, padx=10, pady=1, sticky=tk.W)

key_entry = tk.Entry(root)
key_entry.grid(row=4, column=1, padx=10, pady=1, sticky=tk.EW)
key_entry.insert(0, key)



node_number_label = tk.Label(root, text="Node Number:")
node_number_label.grid(row=5, column=0, padx=10, pady=1, sticky=tk.W)

node_number_entry = tk.Entry(root)
node_number_entry.grid(row=5, column=1, padx=10, pady=1, sticky=tk.EW)
node_number_entry.insert(0, node_number)


separator_label = tk.Label(root, text="____________")
separator_label.grid(row=6, column=0, padx=10, pady=1, sticky=tk.W)


long_name_label = tk.Label(root, text="Long Name:")
long_name_label.grid(row=7, column=0, padx=10, pady=1, sticky=tk.W)

long_name_entry = tk.Entry(root)
long_name_entry.grid(row=7, column=1, padx=10, pady=1, sticky=tk.EW)
long_name_entry.insert(0, client_long_name)


short_name_label = tk.Label(root, text="Short Name:")
short_name_label.grid(row=8, column=0, padx=10, pady=1, sticky=tk.W)

short_name_entry = tk.Entry(root)
short_name_entry.grid(row=8, column=1, padx=10, pady=1, sticky=tk.EW)
short_name_entry.insert(0, client_short_name)

### BUTTONS
connect_button = tk.Button(root, text="Connect", command=connect_mqtt)
connect_button.grid(row=0, column=2, padx=10, pady=1, sticky=tk.EW)

disconnect_button = tk.Button(root, text="Disconnect", command=disconnect_mqtt)
disconnect_button.grid(row=1, column=2, padx=10, pady=1, sticky=tk.EW)

node_info_button = tk.Button(root, text="Send NodeInfo", command=send_node_info)
node_info_button.grid(row=2, column=2, padx=10, pady=1, sticky=tk.EW)

erase_nodedb_button = tk.Button(root, text="Erase NodeDB", command=erase_nodedb)
erase_nodedb_button.grid(row=3, column=2, padx=10, pady=1, sticky=tk.EW)

erase_messagedb_button = tk.Button(root, text="Erase Message History", command=erase_messagedb)
erase_messagedb_button.grid(row=4, column=2, padx=10, pady=1, sticky=tk.EW)


preset_label = tk.Label(root, text="Select Preset:")
preset_label.grid(row=5, column=2, padx=10, pady=1, sticky=tk.W)


preset_var = tk.StringVar(root)
preset_var.set("Select an option")
preset_dropdown = tk.OptionMenu(root, preset_var, "Default", *list(presets.keys()))
preset_dropdown.grid(row=6, column=2, padx=10, pady=1, sticky=tk.EW)
preset_var.trace_add("write", lambda *args: update_preset_dropdown())
update_preset_dropdown()

save_preset_button = tk.Button(root, text="Save Preset", command=save_preset)
save_preset_button.grid(row=7, column=2, padx=10, pady=1, sticky=tk.EW)








### INTERFACE WINDOW
message_history = scrolledtext.ScrolledText(root, wrap=tk.WORD)
message_history.grid(row=9, column=0, columnspan=3, padx=10, pady=10, sticky=tk.NSEW)
message_history.config(state=tk.DISABLED)

### MESSAGE ENTRY
enter_message_label = tk.Label(root, text="Enter message:")
enter_message_label.grid(row=10, column=0, padx=10, pady=1, sticky=tk.W)

message_entry = tk.Entry(root)
message_entry.grid(row=11, column=0, columnspan=3, padx=10, pady=1, sticky=tk.EW)

### MESSAGE ACTION
entry_dm_label = tk.Label(root, text="DM to (click a node):")
entry_dm_label.grid(row=12, column=1, padx=10, pady=1, sticky=tk.E)

entry_dm = tk.Entry(root)
entry_dm.grid(row=12, column=2, padx=10, pady=1, sticky=tk.EW)

broadcast_button = tk.Button(root, text="Broadcast Message", command=lambda: publish_message(broadcast_id))
broadcast_button.grid(row=13, column=0, padx=10, pady=15, sticky=tk.EW)

dm_button = tk.Button(root, text="Direct Message", command=lambda: direct_message(entry_dm.get()))
dm_button.grid(row=13, column=2, padx=10, pady=15, sticky=tk.EW)


### NODE LIST
nodeinfo_window = scrolledtext.ScrolledText(root, wrap=tk.WORD)
nodeinfo_window.grid(row=0, rowspan = 14, column=3, padx=10, pady=1, sticky=tk.NSEW)
nodeinfo_window.bind("<Enter>", on_nodeinfo_enter)
nodeinfo_window.bind("<Leave>", on_nodeinfo_leave)
nodeinfo_window.bind("<Button-1>", on_nodeinfo_click)
nodeinfo_window.config(state=tk.DISABLED)


############################

client = mqtt.Client(client_id="", clean_session=True, userdata=None)
client.on_connect = on_connect
client.on_disconnect = on_disconnect
client.on_message = on_message

# Function to run the MQTT client loop in a separate thread
def mqtt_thread():
    if debug: print("MQTT Thread")
    if debug: 
        if client.is_connected():
            print("client connected")
        else:
            print("client not connected")
    while True:
        client.loop()

mqtt_thread = threading.Thread(target=mqtt_thread, daemon=True)
mqtt_thread.start()

# Function to broadcast NodeInfo in a separate thread
def send_node_info_periodically():
    if client.is_connected():
        send_node_info()

node_info_timer = threading.Timer(node_info_interval_minutes * 60, send_node_info_periodically)
node_info_timer.start()


def on_exit():
    """Function to be called when the GUI is closed."""
    if client.is_connected():
        client.disconnect()
        print("client disconnected")
        db_connection.close()
    root.destroy()
    client.loop_stop()
    node_info_timer.cancel()

# Set the exit handler
root.protocol("WM_DELETE_WINDOW", on_exit)

# Start the main loop
root.mainloop()
