from meshtastic.protobuf import mesh_pb2, telemetry_pb2, portnums_pb2, mqtt_pb2
from encryption import decode_encrypted
from preferences import debug
import preferences
from gui import update_gui
from database_functions import maybe_store_nodeinfo_in_db, maybe_store_position_in_db

from helper_functions import format_time, current_time, sanitize_string

#################################
# Receive Messages

def on_message(client, userdata, msg):						# pylint: disable=unused-argument
    """Callback function that accepts a meshtastic message from mqtt."""

    # if debug:
    #     print("on_message")
    se = mqtt_pb2.ServiceEnvelope()
    is_encrypted: bool = False
    try:
        se.ParseFromString(msg.payload)
        if preferences.print_service_envelope:
            print ("")
            print ("Service Envelope:")
            print (se)
        mp = se.packet

    except Exception as e:
        print(f"*** ServiceEnvelope: {str(e)}")
        return

    if len(msg.payload) > preferences.max_msg_len:
        if debug:
            print('Message too long: ' + str(len(msg.payload)) + ' bytes long, skipping.')
        return

    if mp.HasField("encrypted") and not mp.HasField("decoded"):
        decode_encrypted(mp, key)
        is_encrypted=True
    
    if preferences.print_message_packet:
        print ("")
        print ("Message Packet:")
        print(mp)

    if mp.decoded.portnum == portnums_pb2.TEXT_MESSAGE_APP:
        try:
            text_payload = mp.decoded.payload.decode("utf-8")
            process_message(mp, text_payload, is_encrypted)
            # print(f"{text_payload}")
        except Exception as e:
            print(f"*** TEXT_MESSAGE_APP: {str(e)}")

    elif mp.decoded.portnum == portnums_pb2.NODEINFO_APP:
        info = mesh_pb2.User()
        try:
            info.ParseFromString(mp.decoded.payload)
            maybe_store_nodeinfo_in_db(info)
            if preferences.print_node_info:
                print("")
                print("NodeInfo:")
                print(info)
        except Exception as e:
            print(f"*** NODEINFO_APP: {str(e)}")

    elif mp.decoded.portnum == portnums_pb2.POSITION_APP:
        pos = mesh_pb2.Position()
        try:
            pos.ParseFromString(mp.decoded.payload)
            if preferences.record_locations:
                maybe_store_position_in_db(getattr(mp, "from"), pos, getattr(mp, "rx_rssi"))
        except Exception as e:
            print(f"*** POSITION_APP: {str(e)}")

    elif mp.decoded.portnum == portnums_pb2.TELEMETRY_APP:
        env = telemetry_pb2.Telemetry()
        try:
            env.ParseFromString(mp.decoded.payload)
        except Exception as e:
            print(f"*** TELEMETRY_APP: {str(e)}")

        rssi = getattr(mp, "rx_rssi")

        # Device Metrics
        device_metrics_dict = {
            'Battery Level': env.device_metrics.battery_level,
            'Voltage': round(env.device_metrics.voltage, 2),
            'Channel Utilization': round(env.device_metrics.channel_utilization, 1),
            'Air Utilization': round(env.device_metrics.air_util_tx, 1)
        }
        if rssi:
           device_metrics_dict["RSSI"] = rssi

        # Environment Metrics
        environment_metrics_dict = {
            'Temp': round(env.environment_metrics.temperature, 2),
            'Humidity': round(env.environment_metrics.relative_humidity, 0),
            'Pressure': round(env.environment_metrics.barometric_pressure, 2),
            'Gas Resistance': round(env.environment_metrics.gas_resistance, 2)
        }
        if rssi:
           environment_metrics_dict["RSSI"] = rssi

        # Power Metrics
            # TODO
        # Air Quality Metrics
            # TODO

        if preferences.print_telemetry:
            table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_nodeinfo"
            device_metrics_string = "From: " + get_name_by_id("short", getattr(mp, "from")) + ", "
            environment_metrics_string = "From: " + get_name_by_id("short", getattr(mp, "from")) + ", "

            # Only use metrics that are non-zero
            has_device_metrics = True
            has_environment_metrics = True
            has_device_metrics = all(value != 0 for value in device_metrics_dict.values())
            has_environment_metrics = all(value != 0 for value in environment_metrics_dict.values())

            # Loop through the dictionary and append non-empty values to the string
            for label, value in device_metrics_dict.items():
                if value is not None:
                    device_metrics_string += f"{label}: {value}, "

            for label, value in environment_metrics_dict.items():
                if value is not None:
                    environment_metrics_string += f"{label}: {value}, "

            # Remove the trailing comma and space
            device_metrics_string = device_metrics_string.rstrip(", ")
            environment_metrics_string = environment_metrics_string.rstrip(", ")

            # Print or use the final string
            if has_device_metrics:
                print(device_metrics_string)
            if has_environment_metrics:
                print(environment_metrics_string)

    elif mp.decoded.portnum == portnums_pb2.TRACEROUTE_APP:
        if mp.decoded.payload:
            routeDiscovery = mesh_pb2.RouteDiscovery()
            routeDiscovery.ParseFromString(mp.decoded.payload)

            try:
                route_string = " > ".join(get_name_by_id("long", node) for node in routeDiscovery.route) if routeDiscovery.route else ""
                routeBack_string = " > ".join(get_name_by_id("long", node) for node in routeDiscovery.route_back) if routeDiscovery.route_back else ""

                to_node = get_name_by_id("long", getattr(mp, 'to'))
                from_node = get_name_by_id("long", getattr(mp, 'from'))

                # Build the message without redundant arrows
                routes = [to_node]

                if routeBack_string:
                    routes.append(route_string)

                routes.append(from_node)

                if route_string:
                    routes.append(routeBack_string)

                routes.append(to_node)

                final_route = " > ".join(routes)
                message = f"{format_time(current_time())} >>> Route: {final_route}"

                # Only display traceroutes originating from yourself
                if getattr(mp, 'to') == int(node_number_entry.get()):
                    update_gui(message, tag="info")

            except AttributeError as e:
                print(f"Error accessing route: {e}")
            except Exception as ex:
                print(f"Unexpected error: {ex}")


def process_message(mp, text_payload, is_encrypted):
    """Process a single meshtastic text message."""

    if debug:
        print("process_message")
    if not message_exists(mp):
        from_node = getattr(mp, "from")
        to_node = getattr(mp, "to")

        # Needed for ACK
        message_id = getattr(mp, "id")
        want_ack: bool = getattr(mp, "want_ack")

        sender_short_name = get_name_by_id("short", from_node)
        receiver_short_name = get_name_by_id("short", to_node)
        display_str = ""
        private_dm = False

        if to_node == node_number:
            display_str = f"{format_time(current_time())} DM from {sender_short_name}: {text_payload}"
            if display_dm_emoji:
                display_str = display_str[:9] + dm_emoji + display_str[9:]
            if want_ack is True:
                send_ack(from_node, message_id)

        elif from_node == node_number and to_node != BROADCAST_NUM:
            display_str = f"{format_time(current_time())} DM to {receiver_short_name}: {text_payload}"

        elif from_node != node_number and to_node != BROADCAST_NUM:
            if display_private_dms:
                display_str = f"{format_time(current_time())} DM from {sender_short_name} to {receiver_short_name}: {text_payload}"
                if display_dm_emoji:
                    display_str = display_str[:9] + dm_emoji + display_str[9:]
            else:
                if debug:
                    print("Private DM Ignored")
                private_dm = True

        else:
            display_str = f"{format_time(current_time())} {sender_short_name}: {text_payload}"

        if is_encrypted and not private_dm:
            color="encrypted"
            if display_encrypted_emoji:
                display_str = display_str[:9] + encrypted_emoji + display_str[9:]
        else:
            color="unencrypted"
        if not private_dm:
            update_gui(display_str, text_widget=message_history, tag=color)
        m_id = getattr(mp, "id")
        insert_message_to_db(current_time(), sender_short_name, text_payload, m_id, is_encrypted)

        text = {
            "message": text_payload,
            "from": getattr(mp, "from"),
            "id": getattr(mp, "id"),
            "to": getattr(mp, "to")
        }
        rssi = getattr(mp, "rx_rssi")
        if rssi:
            text["RSSI"] = rssi
        if preferences.print_text_message:
            print("")
            print(text)
    else:
        if debug:
            print("duplicate message ignored")


def message_exists(mp) -> bool:
    """Check for message id in db, ignore duplicates."""

    if debug:
        print("message_exists")
    try:
        table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_messages"

        with sqlite3.connect(db_file_path) as db_connection:
            db_cursor = db_connection.cursor()

            # Check if a record with the same message_id already exists
            existing_record = db_cursor.execute(f'SELECT * FROM {table_name} WHERE message_id=?', (str(getattr(mp, "id")),)).fetchone()

            return existing_record is not None

    except sqlite3.Error as e:
        print(f"SQLite error in message_exists: {e}")

    finally:
        db_connection.close()

    return False