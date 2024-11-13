from meshtastic import BROADCAST_NUM
import time
import ssl
from preferences import debug, auto_reconnect, auto_reconnect_delay
from gui import move_text_up, update_gui, clear_node_window, update_node_list, get_entry
from database_functions import setup_db, load_message_history_from_db
from helper_functions import format_time, current_time
from tx_message_handler import send_node_info, send_position

#################################
# MQTT Server

def connect_mqtt(client):
    """Connect to the MQTT server."""

    if "tls_configured" not in connect_mqtt.__dict__:          #Persistent variable to remember if we've configured TLS yet
        connect_mqtt.tls_configured = False

    if debug:
        print("connect_mqtt")
    # global mqtt_broker, mqtt_port, mqtt_username, mqtt_password, root_topic, channel, node_number, db_file_path, key
    if not client.is_connected():
        try:
            mqtt_broker = get_entry("mqtt_broker")
            if ':' in mqtt_broker:
                mqtt_broker,mqtt_port = mqtt_broker.split(':')
                mqtt_port = int(mqtt_port)

            mqtt_username = get_entry("mqtt_username")
            mqtt_password = get_entry("mqtt_password")
            root_topic = get_entry("root_topic")
            channel = get_entry("channel")

            key = get_entry("key")

            if key == "AQ==":
                if debug:
                    print("key is default, expanding to AES128")
                key = "1PG7OiApB1nwvP+rz05pAQ=="

            if not move_text_up(): # copy ID to Number and test for 8 bit hex
                return
            
            node_number = int(get_entry("node_number"))  # Convert the input to an integer

            padded_key = key.ljust(len(key) + ((4 - (len(key) % 4)) % 4), '=')
            replaced_key = padded_key.replace('-', '+').replace('_', '/')
            key = replaced_key

            if debug:
                print (f"padded & replaced key = {key}")

            setup_db()

            client.username_pw_set(mqtt_username, mqtt_password)
            if mqtt_port == 8883 and connect_mqtt.tls_configured is False:
                client.tls_set(ca_certs="cacert.pem", tls_version=ssl.PROTOCOL_TLSv1_2)
                client.tls_insecure_set(False)
                connect_mqtt.tls_configured = True
            client.connect(mqtt_broker, mqtt_port, 60)
            update_gui(f"{format_time(current_time())} >>> Connecting to MQTT broker at {mqtt_broker}...", tag="info")

        except Exception as e:
            update_gui(f"{format_time(current_time())} >>> Failed to connect to MQTT broker: {str(e)}", tag="info")

        update_node_list()
    elif client.is_connected() and get_entry("channel") is not channel:
        print("Channel has changed, disconnect and reconnect")
        if auto_reconnect:
            print("auto_reconnect disconnecting from MQTT broker")
            disconnect_mqtt(client)
            time.sleep(auto_reconnect_delay)
            print("auto_reconnect connecting to MQTT broker")
            connect_mqtt(client)

    else:
        update_gui(f"{format_time(current_time())} >>> Already connected to {mqtt_broker}", tag="info")


def disconnect_mqtt(client):
    """Disconnect from the MQTT server."""

    if debug:
        print("disconnect_mqtt")
    if client.is_connected():
        client.disconnect()
        update_gui(f"{format_time(current_time())} >>> Disconnected from MQTT broker", tag="info")
        # Clear the display
        clear_node_window()

    else:
        update_gui("Already disconnected", tag="info")


def set_topic(root_topic, channel):
    """?"""

    if debug:
        print("set_topic")
    global subscribe_topic, publish_topic, node_number, node_name
    node_name = '!' + hex(node_number)[2:]
    subscribe_topic = root_topic + channel + "/#"
    publish_topic = root_topic + channel + "/" + node_name


def on_connect(client, userdata, flags, reason_code, properties):		# pylint: disable=unused-argument
    """?"""

    set_topic(get_entry("root_topic"), get_entry("channel"))

    if debug:
        print("on_connect")
        if client.is_connected():
            print("client is connected")

    if reason_code == 0:
        load_message_history_from_db()
        if debug:
            print(f"Subscribe Topic is: {subscribe_topic}")
        client.subscribe(subscribe_topic)
        message = f"{format_time(current_time())} >>> Connected to {get_entry("mqtt_broker")} on topic {get_entry("channel")} as {'!' + hex(node_number)[2:]}"
        update_gui(message, tag="info")
        send_node_info(BROADCAST_NUM, want_response=False)

        if get_entry("lon") and get_entry("lat"):
            send_position(BROADCAST_NUM)

    else:
        message = f"{format_time(current_time())} >>> Failed to connect to MQTT broker with result code {str(reason_code)}"
        update_gui(message, tag="info")


def on_disconnect(client, userdata, flags, reason_code, properties):		# pylint: disable=unused-argument
    """?"""

    if debug:
        print("on_disconnect")
    if reason_code != 0:
        message = f"{format_time(current_time())} >>> Disconnected from MQTT broker with result code {str(reason_code)}"
        update_gui(message, tag="info")
        if auto_reconnect is True:
            print("attempting to reconnect in " + str(auto_reconnect_delay) + " second(s)")
            time.sleep(auto_reconnect_delay)
            connect_mqtt(client)
