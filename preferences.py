from meshtastic.protobuf import mesh_pb2

#################################
### Debug Options
debug: bool = False
auto_reconnect: bool = False
auto_reconnect_delay: float = 1 # seconds
print_service_envelope: bool = False
print_message_packet: bool = False
print_text_message: bool = False
print_node_info: bool =  False
print_telemetry: bool = False
print_failed_encryption_packet: bool = False
print_position_report: bool = False
color_text: bool = False
display_encrypted_emoji: bool = True
display_dm_emoji: bool = True
display_lookup_button: bool = False
display_private_dms: bool = False

record_locations: bool = False

#################################
### Default settings
mqtt_broker = "mqtt.meshtastic.org"
mqtt_port = 1883
mqtt_username = "meshdev"
mqtt_password = "large4cats"
root_topic = "msh/US/2/e/"
channel = "LongFast"
key = "AQ=="
max_msg_len = mesh_pb2.Constants.DATA_PAYLOAD_LEN
key_emoji = "\U0001F511"
encrypted_emoji = "\U0001F512"
dm_emoji = "\u2192"

client_short_name = "MCM"
client_long_name = "MQTTastic"
lat = ""
lon = ""
alt = ""
client_hw_model = 255
node_info_interval_minutes = 15