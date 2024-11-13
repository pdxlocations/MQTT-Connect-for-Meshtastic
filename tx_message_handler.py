import preferences
from mqtt_server import connect_mqtt

#################################
# Send Messages

def direct_message(client, destination_id):
    """Send a direct message."""

    if preferences.debug:
        print("direct_message")
    if destination_id:
        try:
            destination_id = int(destination_id[1:], 16)
            publish_message(client, destination_id)
        except Exception as e:
            if preferences.debug:
                print(f"Error converting destination_id: {e}")

def publish_message(client, destination_id):
    """?"""

    if preferences.debug:
        print("publish_message")

    if not client.is_connected():
        connect_mqtt()

    message_text = message_entry.get()
    if message_text:
        encoded_message = mesh_pb2.Data()
        encoded_message.portnum = portnums_pb2.TEXT_MESSAGE_APP
        encoded_message.payload = message_text.encode("utf-8")
        generate_mesh_packet(destination_id, encoded_message)
        message_entry.delete(0, 'end')
    #else:
    #    return


def send_traceroute(destination_id):
    """Send traceroute request to destination_id."""

    if debug:
        print("send_TraceRoute")

    if not client.is_connected():
        message =  format_time(current_time()) + " >>> Connect to a broker before sending traceroute"
        update_gui(message, tag="info")
    else:
        message =  format_time(current_time()) + " >>> Sending Traceroute Packet"
        update_gui(message, tag="info")

        if debug:
            print(f"Sending Traceroute Packet to {str(destination_id)}")

        encoded_message = mesh_pb2.Data()
        encoded_message.portnum = portnums_pb2.TRACEROUTE_APP
        encoded_message.want_response = True

        destination_id = int(destination_id[1:], 16)
        generate_mesh_packet(destination_id, encoded_message)

def send_node_info(destination_id, want_response):
    """Send my node information to the specified destination."""

    global node_number

    if debug:
        print("send_node_info")

    if not client.is_connected():
        message =  format_time(current_time()) + " >>> Connect to a broker before sending nodeinfo"
        update_gui(message, tag="info")
    else:
        if not move_text_up(): # copy ID to Number and test for 8 bit hex
            return
        
        if destination_id == BROADCAST_NUM:
            message =  format_time(current_time()) + " >>> Broadcast NodeInfo Packet"
            update_gui(message, tag="info")
        else:
            if debug:
                print(f"Sending NodeInfo Packet to {str(destination_id)}")

        node_number = int(node_number_entry.get())

        decoded_client_id = bytes(node_name, "utf-8")
        decoded_client_long = bytes(long_name_entry.get(), "utf-8")
        decoded_client_short = bytes(short_name_entry.get(), "utf-8")
        decoded_client_hw_model = preferences.client_hw_model

        user_payload = mesh_pb2.User()
        setattr(user_payload, "id", decoded_client_id)
        setattr(user_payload, "long_name", decoded_client_long)
        setattr(user_payload, "short_name", decoded_client_short)
        setattr(user_payload, "hw_model", decoded_client_hw_model)

        user_payload = user_payload.SerializeToString()

        encoded_message = mesh_pb2.Data()
        encoded_message.portnum = portnums_pb2.NODEINFO_APP
        encoded_message.payload = user_payload
        encoded_message.want_response = want_response  # Request NodeInfo back

        # print(encoded_message)
        generate_mesh_packet(destination_id, encoded_message)


def send_position(destination_id) -> None:
    """Send current position to destination_id (which can be a broadcast.)"""

    global node_number

    if debug:
        print("send_Position")

    if not client.is_connected():
        message =  format_time(current_time()) + " >>> Connect to a broker before sending position"
        update_gui(message, tag="info")
    else:
        if destination_id == BROADCAST_NUM:
            message =  format_time(current_time()) + " >>> Broadcast Position Packet"
            update_gui(message, tag="info")
        else:
            if debug:
                print(f"Sending Position Packet to {str(destination_id)}")

        node_number = int(node_number_entry.get())
        pos_time = int(time.time())

        latitude_str = lat_entry.get()
        longitude_str = lon_entry.get()

        try:
            latitude = float(latitude_str)  # Convert latitude to a float
        except ValueError:
            latitude = 0.0
        try:
            longitude = float(longitude_str)  # Convert longitude to a float
        except ValueError:
            longitude = 0.0

        latitude = latitude * 1e7
        longitude = longitude * 1e7

        latitude_i = int(latitude)
        longitude_i = int(longitude)

        altitude_str = alt_entry.get()
        altitude_units = 1 / 3.28084 if 'ft' in altitude_str else 1.0
        altitude_number_of_units = float(re.sub('[^0-9.]','', altitude_str))
        altitude_i = int(altitude_units * altitude_number_of_units) # meters

        position_payload = mesh_pb2.Position()
        setattr(position_payload, "latitude_i", latitude_i)
        setattr(position_payload, "longitude_i", longitude_i)
        setattr(position_payload, "altitude", altitude_i)
        setattr(position_payload, "time", pos_time)

        position_payload = position_payload.SerializeToString()

        encoded_message = mesh_pb2.Data()
        encoded_message.portnum = portnums_pb2.POSITION_APP
        encoded_message.payload = position_payload
        encoded_message.want_response = True

        generate_mesh_packet(destination_id, encoded_message)



def generate_mesh_packet(destination_id, encoded_message):
    """Send a packet out over the mesh."""

    global global_message_id
    mesh_packet = mesh_pb2.MeshPacket()

    # Use the global message ID and increment it for the next call
    mesh_packet.id = global_message_id
    global_message_id += 1

    setattr(mesh_packet, "from", node_number)
    mesh_packet.to = destination_id
    mesh_packet.want_ack = False
    mesh_packet.channel = generate_hash(channel, key)
    mesh_packet.hop_limit = 3


    if key == "":
        mesh_packet.decoded.CopyFrom(encoded_message)
        if debug:
            print("key is none")
    else:
        print (f"channel{channel}")
        print (f"key{key}")
        print (f"mesh_packet{mesh_packet}")
        print (f"encoded message{encoded_message}")



        mesh_packet.encrypted = encrypt_message(channel, key, mesh_packet, encoded_message, node_number)
        if debug:
            print("key present")

    service_envelope = mqtt_pb2.ServiceEnvelope()
    service_envelope.packet.CopyFrom(mesh_packet)
    service_envelope.channel_id = channel
    service_envelope.gateway_id = node_name
    # print (service_envelope)

    payload = service_envelope.SerializeToString()
    set_topic(root_topic, channel)
    # print(payload)
    client.publish(publish_topic, payload)





def send_ack(destination_id, message_id):
    "Return a meshtastic acknowledgement."""
    if debug:
        print("Sending ACK")

    encoded_message = mesh_pb2.Data()
    encoded_message.portnum = portnums_pb2.ROUTING_APP
    encoded_message.request_id = message_id
    encoded_message.payload = b"\030\000"

    generate_mesh_packet(destination_id, encoded_message)
