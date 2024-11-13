import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import tkinter.messagebox
import sqlite3

from preferences import debug, display_lookup_button, color_text

from helper_functions import sanitize_string, is_valid_hex
from tx_message_handler import direct_message, send_node_info


def build_gui(entries):
    ############################
    # GUI Layout

    global mqtt_broker_entry, mqtt_username_entry, mqtt_password_entry, root_topic_entry, channel_entry, key_entry
    global node_number_entry, node_id_entry, long_name_entry, short_name_entry, lat_entry, lon_entry, alt_entry
    global nodeinfo_window


    root = tk.Tk()
    root.title("Meshtastic MQTT Connect")

    # Create PanedWindow
    paned_window = tk.PanedWindow(root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
    paned_window.grid(row=0, column=0, padx=5, pady=5, sticky=tk.NSEW)

    # Log Frame
    message_log_frame = tk.Frame(paned_window)
    paned_window.add(message_log_frame)

    # Info Frame
    node_info_frame = tk.Frame(paned_window)
    paned_window.add(node_info_frame)

    # Set weights for resizable frames
    paned_window.paneconfigure(message_log_frame)
    paned_window.paneconfigure(node_info_frame)

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)
    message_log_frame.grid_rowconfigure(11, weight=1)
    message_log_frame.grid_columnconfigure(1, weight=1)
    message_log_frame.grid_columnconfigure(2, weight=1)
    node_info_frame.grid_rowconfigure(0, weight=1)
    node_info_frame.grid_columnconfigure(0, weight=1)

    w = 1200 # ~width for the Tk root
    h = 900 # ~height for the Tk root

    ws = root.winfo_screenwidth() # width of the screen
    hs = root.winfo_screenheight() # height of the screen
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)

    root.geometry("+%d+%d" %(x,y))
    # root.resizable(0,0)

    ### SERVER SETTINGS
    mqtt_broker_label = tk.Label(message_log_frame, text="MQTT Broker:")
    mqtt_broker_label.grid(row=0, column=0, padx=5, pady=1, sticky=tk.W)

    mqtt_broker_entry = tk.Entry(message_log_frame)
    mqtt_broker_entry.grid(row=0, column=1, padx=5, pady=1, sticky=tk.EW)
    # mqtt_broker_entry.insert(0, mqtt_broker)


    mqtt_username_label = tk.Label(message_log_frame, text="MQTT Username:")
    mqtt_username_label.grid(row=1, column=0, padx=5, pady=1, sticky=tk.W)

    mqtt_username_entry = tk.Entry(message_log_frame)
    mqtt_username_entry.grid(row=1, column=1, padx=5, pady=1, sticky=tk.EW)
    # mqtt_username_entry.insert(0, mqtt_username)


    mqtt_password_label = tk.Label(message_log_frame, text="MQTT Password:")
    mqtt_password_label.grid(row=2, column=0, padx=5, pady=1, sticky=tk.W)

    mqtt_password_entry = tk.Entry(message_log_frame, show="*")
    mqtt_password_entry.grid(row=2, column=1, padx=5, pady=1, sticky=tk.EW)
    # mqtt_password_entry.insert(0, mqtt_password)


    root_topic_label = tk.Label(message_log_frame, text="Root Topic:")
    root_topic_label.grid(row=3, column=0, padx=5, pady=1, sticky=tk.W)

    root_topic_entry = tk.Entry(message_log_frame)
    root_topic_entry.grid(row=3, column=1, padx=5, pady=1, sticky=tk.EW)
    # root_topic_entry.insert(0, root_topic)


    channel_label = tk.Label(message_log_frame, text="Channel:")
    channel_label.grid(row=4, column=0, padx=5, pady=1, sticky=tk.W)

    channel_entry = tk.Entry(message_log_frame)
    channel_entry.grid(row=4, column=1, padx=5, pady=1, sticky=tk.EW)
    # channel_entry.insert(0, channel)


    key_label = tk.Label(message_log_frame, text="Key:")
    key_label.grid(row=5, column=0, padx=5, pady=1, sticky=tk.W)

    key_entry = tk.Entry(message_log_frame)
    key_entry.grid(row=5, column=1, padx=5, pady=1, sticky=tk.EW)
    # key_entry.insert(0, key)





    id_frame = tk.Frame(message_log_frame)
    id_frame.grid(row=6, column=0, columnspan=2, sticky=tk.EW)

    id_frame.columnconfigure(0, weight=0)
    id_frame.columnconfigure(1, weight=0)  # Button columns don't expand
    id_frame.columnconfigure(2, weight=1)

    node_number_label = tk.Label(id_frame, text="Node Number:")
    node_number_label.grid(row=0, column=0, padx=5, pady=1, sticky=tk.W)

    up_button = tk.Button(id_frame, text="↑", command=move_text_up)
    up_button.grid(row=0, column=1)

    node_number_entry = tk.Entry(id_frame)
    node_number_entry.grid(row=0, column=2, padx=5, pady=1, sticky=tk.EW)
    # node_number_entry.insert(0, node_number)


    node_id_label = tk.Label(id_frame, text="Node ID:")
    node_id_label.grid(row=1, column=0, padx=5, pady=1, sticky=tk.W)

    down_button = tk.Button(id_frame, text="↓", command=move_text_down)
    down_button.grid(row=1, column=1)

    node_id_entry = tk.Entry(id_frame)
    node_id_entry.grid(row=1, column=2, padx=5, pady=1, sticky=tk.EW)
    move_text_down()


    separator_label = tk.Label(message_log_frame, text="____________")
    separator_label.grid(row=7, column=0, padx=5, pady=1, sticky=tk.W)


    long_name_label = tk.Label(message_log_frame, text="Long Name:")
    long_name_label.grid(row=8, column=0, padx=5, pady=1, sticky=tk.W)

    long_name_entry = tk.Entry(message_log_frame)
    long_name_entry.grid(row=8, column=1, padx=5, pady=1, sticky=tk.EW)
    # long_name_entry.insert(0, client_long_name)

    short_name_label = tk.Label(message_log_frame, text="Short Name:")
    short_name_label.grid(row=9, column=0, padx=5, pady=1, sticky=tk.W)

    short_name_entry = tk.Entry(message_log_frame)
    short_name_entry.grid(row=9, column=1, padx=5, pady=1, sticky=tk.EW)
    # short_name_entry.insert(0, client_short_name)


    pos_frame = tk.Frame(message_log_frame)
    pos_frame.grid(row=10, column=0, columnspan=2, sticky=tk.EW)

    lat_label = tk.Label(pos_frame, text="Lat:")
    lat_label.grid(row=0, column=0, padx=5, pady=1, sticky=tk.EW)

    lat_entry = tk.Entry(pos_frame, width=8)
    lat_entry.grid(row=0, column=1, padx=5, pady=1, sticky=tk.EW)
    # lat_entry.insert(0, lat)

    lon_label = tk.Label(pos_frame, text="Lon:")
    lon_label.grid(row=0, column=3, padx=5, pady=1, sticky=tk.EW)

    lon_entry = tk.Entry(pos_frame, width=8)
    lon_entry.grid(row=0, column=4, padx=5, pady=1, sticky=tk.EW)
    # lon_entry.insert(0, lon)

    alt_label = tk.Label(pos_frame, text="Alt:")
    alt_label.grid(row=0, column=5, padx=5, pady=1, sticky=tk.EW)

    alt_entry = tk.Entry(pos_frame, width=8)
    alt_entry.grid(row=0, column=6, padx=5, pady=1, sticky=tk.EW)
    # alt_entry.insert(0, alt)


    ### BUTTONS


    button_frame = tk.Frame(message_log_frame)
    button_frame.grid(row=0, column=2, rowspan=11, sticky=tk.NSEW)

    preset_label = tk.Label(button_frame, text="Select Preset:")
    preset_label.grid(row=0, column=2, padx=5, pady=1, sticky=tk.W)

    preset_var = tk.StringVar(button_frame)
    preset_var.set("None")
    preset_dropdown = tk.OptionMenu(button_frame, preset_var, "Default", *list(presets.keys()))
    preset_dropdown.grid(row=1, column=2, padx=5, pady=1, sticky=tk.EW)
    preset_var.trace_add("write", lambda *args: update_preset_dropdown())
    update_preset_dropdown()

    connect_button = tk.Button(button_frame, text="Connect", command=connect_mqtt)
    connect_button.grid(row=2, column=2, padx=5, pady=1, sticky=tk.EW)

    disconnect_button = tk.Button(button_frame, text="Disconnect", command=disconnect_mqtt)
    disconnect_button.grid(row=3, column=2, padx=5, pady=1, sticky=tk.EW)

    node_info_button = tk.Button(button_frame, text="Send NodeInfo", command=lambda: send_node_info(BROADCAST_NUM, want_response=True))
    node_info_button.grid(row=4, column=2, padx=5, pady=1, sticky=tk.EW)

    erase_nodedb_button = tk.Button(button_frame, text="Erase NodeDB", command=erase_nodedb)
    erase_nodedb_button.grid(row=5, column=2, padx=5, pady=1, sticky=tk.EW)

    erase_messagedb_button = tk.Button(button_frame, text="Erase Message History", command=erase_messagedb)
    erase_messagedb_button.grid(row=6, column=2, padx=5, pady=1, sticky=tk.EW)

    save_preset_button = tk.Button(button_frame, text="Save Preset", command=save_preset)
    save_preset_button.grid(row=7, column=2, padx=5, pady=1, sticky=tk.EW)


    ### INTERFACE WINDOW
    message_history = scrolledtext.ScrolledText(message_log_frame, wrap=tk.WORD)
    message_history.grid(row=11, column=0, columnspan=3, padx=5, pady=10, sticky=tk.NSEW)
    message_history.config(state=tk.DISABLED)

    if color_text:
        message_history.tag_config('dm', background='light goldenrod')
        message_history.tag_config('encrypted', background='green')
        message_history.tag_config('info', foreground='gray')

    ### MESSAGE ENTRY
    enter_message_label = tk.Label(message_log_frame, text="Enter message:")
    enter_message_label.grid(row=12, column=0, padx=5, pady=1, sticky=tk.W)

    message_entry = tk.Entry(message_log_frame)
    message_entry.grid(row=13, column=0, columnspan=3, padx=5, pady=1, sticky=tk.EW)

    ### MESSAGE ACTION
    entry_dm_label = tk.Label(message_log_frame, text="DM to (click a node):")
    entry_dm_label.grid(row=14, column=1, padx=5, pady=1, sticky=tk.E)

    entry_dm = tk.Entry(message_log_frame)
    entry_dm.grid(row=14, column=2, padx=5, pady=1, sticky=tk.EW)

    broadcast_button = tk.Button(message_log_frame, text="Broadcast Message", command=lambda: publish_message(BROADCAST_NUM))
    broadcast_button.grid(row=15, column=0, padx=5, pady=1, sticky=tk.EW)

    dm_button = tk.Button(message_log_frame, text="Direct Message", command=lambda: direct_message(entry_dm.get()))
    dm_button.grid(row=15, column=2, padx=5, pady=1, sticky=tk.EW)

    tr_button = tk.Button(message_log_frame, text="Trace Route", command=lambda: send_traceroute(entry_dm.get()))
    tr_button.grid(row=16, column=2, padx=5, pady=1 if display_lookup_button else (1,5), sticky=tk.EW)

    if display_lookup_button:
        def lookup_action():
            entry_value = entry_dm.get()[1:]  # Get the string without the first character
            if entry_value:  # Check if the string is not empty
                try:
                    hex_value = int(entry_value, 16)
                    get_name_by_id("short", hex_value)
                except ValueError:
                    print("Invalid hex value")
            else:
                print("Entry is empty")
        
        lookup_button = tk.Button(message_log_frame, text="Lookup", command=lookup_action)
        lookup_button.grid(row=17, column=2, padx=5, pady=(1,5), sticky=tk.EW)

    ### NODE LIST
    nodeinfo_window = scrolledtext.ScrolledText(node_info_frame, wrap=tk.WORD, width=50)
    nodeinfo_window.grid(row=0, column=0, padx=5, pady=1, sticky=tk.NSEW)
    nodeinfo_window.bind("<Enter>", on_nodeinfo_enter)
    nodeinfo_window.bind("<Leave>", on_nodeinfo_leave)
    nodeinfo_window.bind("<Button-1>", on_nodeinfo_click)
    nodeinfo_window.config(state=tk.DISABLED)


def load_preset():
    """Function to load the selected preset."""

    if debug:
        print("load_preset")
    selected_preset_name = preset_var.get()

    if selected_preset_name in presets:
        selected_preset = presets[selected_preset_name]
        if debug:
            print(f"Loading preset: {selected_preset_name}")

        mqtt_broker_entry.delete(0, tk.END)
        mqtt_broker_entry.insert(0, selected_preset.broker)
        mqtt_username_entry.delete(0, tk.END)
        mqtt_username_entry.insert(0, selected_preset.username)
        mqtt_password_entry.delete(0, tk.END)
        mqtt_password_entry.insert(0, selected_preset.password)
        root_topic_entry.delete(0, tk.END)
        root_topic_entry.insert(0, selected_preset.root_topic)
        channel_entry.delete(0, tk.END)
        channel_entry.insert(0, selected_preset.channel)
        key_entry.delete(0, tk.END)
        key_entry.insert(0, selected_preset.key)
        node_number_entry.delete(0, tk.END)
        node_number_entry.insert(0, selected_preset.node_number)
        move_text_down()
        long_name_entry.delete(0, tk.END)
        long_name_entry.insert(0, selected_preset.long_name)
        short_name_entry.delete(0, tk.END)
        short_name_entry.insert(0, selected_preset.short_name)
        lat_entry.delete(0, tk.END)
        lat_entry.insert(0, selected_preset.lat)
        lon_entry.delete(0, tk.END)
        lon_entry.insert(0, selected_preset.lon)
        alt_entry.delete(0, tk.END)
        alt_entry.insert(0, selected_preset.alt)
    else:
        print(f"Error: Preset '{selected_preset_name}' not found.")


def update_preset_dropdown():
    """Update the preset dropdown menu."""

    preset_names = list(presets.keys())
    menu = preset_dropdown["menu"]
    menu.delete(0, 'end')
    for preset_name in preset_names:
        menu.add_command(label=preset_name, command=tk._setit(preset_var, preset_name, lambda *args: load_preset()))


def preset_var_changed(*args):
    """?"""

    selected_option = preset_var.get()
    update_preset_dropdown()
    print(f"Selected Option: {selected_option}")


def save_presets_to_file():
    """?"""
    if debug:
        print("save_presets_to_file")
    with open(presets_file_path, "w") as file:
        json.dump({name: preset.__dict__ for name, preset in presets.items()}, file, indent=2)


def load_presets_from_file():
    """Load presets from a file."""

    if debug:
        print("load_presets_from_file")
    try:
        with open(presets_file_path, "r") as file:
            loaded_presets = json.load(file)
            return {name: Preset(**data) for name, data in loaded_presets.items()}
    except FileNotFoundError:
        return {}
    

def get_entry(key=None) -> dict:
    entries = {
        "mqtt_broker": mqtt_broker_entry.get(),
        "mqtt_username": mqtt_username_entry.get(),
        "mqtt_password": mqtt_password_entry.get(),
        "root_topic": root_topic_entry.get(),
        "channel": channel_entry.get(),
        "key": key_entry.get(),
        "node_number": node_number_entry.get(),
        "node_id": node_id_entry.get(),
        "long_name": long_name_entry.get(),
        "short_name": short_name_entry.get(),
        "lat": lat_entry.get(),
        "lon": lon_entry.get(),
        "alt": alt_entry.get()
    }
    if key:
        return entries.get(key)
    return entries


############################
# GUI Functions

def update_node_list():
    """?"""

    try:
        table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_nodeinfo"

        with sqlite3.connect(db_file_path) as db_connection:
            db_cursor = db_connection.cursor()

            # Fetch all nodes from the database
            nodes = db_cursor.execute(f'SELECT user_id, long_name, short_name FROM {table_name}').fetchall()

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


def update_gui(text_payload, tag=None, text_widget=None):
    """?"""

    text_widget = text_widget or message_history
    if debug:
        print(f"updating GUI with: {text_payload}")
    text_widget.config(state=tk.NORMAL)
    text_widget.insert(tk.END, f"{text_payload}\n", tag)
    text_widget.config(state=tk.DISABLED)
    text_widget.yview(tk.END)


def on_nodeinfo_enter(event):							# pylint: disable=unused-argument
    """Change the cursor to a pointer when hovering over text."""
    nodeinfo_window.config(cursor="cross")


def on_nodeinfo_leave(event):							# pylint: disable=unused-argument
    """Change the cursor back to the default when leaving the widget."""
    nodeinfo_window.config(cursor="")


def on_nodeinfo_click(event):							# pylint: disable=unused-argument
    """?"""

    if debug:
        print("on_nodeinfo_click")

    # Get the index of the clicked position
    index = nodeinfo_window.index(tk.CURRENT)

    # Extract the user_id from the clicked line
    clicked_line = nodeinfo_window.get(index + "linestart", index + "lineend")
    to_id = clicked_line.split(",")[0].strip()

    # Update the "to" variable with the clicked user_id
    entry_dm.delete(0, tk.END)
    entry_dm.insert(0, to_id)


def move_text_up():
    """?"""

    text = node_id_entry.get()
    if not is_valid_hex(text, 8, 8):
        print ("Not valid Hex")
        messagebox.showwarning("Warning", "Not a valid Hex ID")
        return False
    else:
        text = int(text.replace("!", ""), 16)
        node_number_entry.delete(0, "end")
        node_number_entry.insert(0, text)
        return True


def move_text_down():
    """?"""

    text = node_number_entry.get()
    text = '!{}'.format(hex(int(text))[2:])

    if not is_valid_hex(text, 8, 8):
        print ("Not valid Hex")
        messagebox.showwarning("Warning", "Not a valid Hex ID")
        return False
    else:
        node_id_entry.delete(0, "end")
        node_id_entry.insert(0, text)
        return True


def clear_node_window():
    nodeinfo_window.config(state=tk.NORMAL)
    nodeinfo_window.delete('1.0', tk.END)
    nodeinfo_window.config(state=tk.DISABLED)