# preset_handler.py
import json
import tkinter as tk

class Preset:
    def __init__(self, name, broker, username, password, root_topic, channel, key, node_number, long_name, short_name, lat, lon, alt):
        self.name = name
        self.broker = broker
        self.username = username
        self.password = password
        self.root_topic = root_topic
        self.channel = channel
        self.key = key
        self.node_number = node_number
        self.long_name = long_name
        self.short_name = short_name
        self.lat = lat
        self.lon = lon
        self.alt = alt

    def to_dict(self):
        return {
            'name': self.name,
            'broker': self.broker,
            'username': self.username,
            'password': self.password,
            'root_topic': self.root_topic,
            'channel': self.channel,
            'key': self.key,
            'node_number': self.node_number,
            'long_name': self.long_name,
            'short_name': self.short_name,
            'lat': self.lat,
            'lon': self.lon,
            'alt': self.alt
        }


def save_preset(presets, preset_var, update_preset_dropdown, entries, debug=False):
    """Save preset values to disk."""
    if debug:
        print("save_preset")
    name = tk.simpledialog.askstring("Save Preset", "Enter preset name:")
    if name is None:  # User clicked Cancel
        return

    # Extract values from the entry fields
    preset = Preset(
        name,
        entries['mqtt_broker'].get(),
        entries['mqtt_username'].get(),
        entries['mqtt_password'].get(),
        entries['root_topic'].get(),
        entries['channel'].get(),
        entries['key'].get(),
        entries['node_number'].get(),
        entries['long_name'].get(),
        entries['short_name'].get(),
        entries['lat'].get(),
        entries['lon'].get(),
        entries['alt'].get()
    )

    presets[name] = preset
    update_preset_dropdown()
    preset_var.set(name)
    save_presets_to_file(presets)

def load_preset(preset_var, presets, debug=False):
    if debug:
        print("load_preset")
    selected_preset_name = preset_var.get()
    # Load the rest of the preset fields

def save_presets_to_file(presets, presets_file_path="presets.json", debug=False):
    if debug:
        print("save_presets_to_file")
    with open(presets_file_path, "w") as file:
        json.dump({name: preset.__dict__ for name, preset in presets.items()}, file, indent=2)

def load_presets_from_file(presets_file_path="presets.json", debug=False):
    if debug:
        print("load_presets_from_file")
    try:
        with open(presets_file_path, "r") as file:
            loaded_presets = json.load(file)
            return {name: Preset(**data) for name, data in loaded_presets.items()}
    except FileNotFoundError:
        return {}
    





