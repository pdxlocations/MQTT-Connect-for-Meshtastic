import sqlite3

from helper_functions import sanitize_string
import preferences


#################################
# Database Handling

# Create database table for NodeDB & Messages
def setup_db():
    """Create the initial database and the nodeinfo, messages, and positions tables in it."""
    if preferences.debug:
        print("setup_db")

    with sqlite3.connect(db_file_path) as db_connection:
        db_cursor = db_connection.cursor()

    # Create the nodeinfo table for storing nodeinfos
    table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_nodeinfo"
    query = f'CREATE TABLE IF NOT EXISTS {table_name} (user_id TEXT, long_name TEXT, short_name TEXT)'
    db_cursor.execute(query)

    # Create the messages table for storing messages
    table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_messages"
    query = f'CREATE TABLE IF NOT EXISTS {table_name} (timestamp TEXT,sender TEXT,content TEXT,message_id TEXT, is_encrypted INTEGER)'
    db_cursor.execute(query)

    # Create the positions new table for storing positions
    table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_positions"
    query = f'CREATE TABLE IF NOT EXISTS {table_name} (node_id TEXT,short_name TEXT,timestamp TEXT,latitude REAL,longitude REAL)'
    db_cursor.execute(query)

    db_connection.commit()
    db_connection.close()


def maybe_store_nodeinfo_in_db(info):
    """Save nodeinfo in sqlite unless that record is already there."""

    if debug:
        print("node info packet received: Checking for existing entry in DB")

    table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_nodeinfo"

    try:
        with sqlite3.connect(db_file_path) as db_connection:
            db_cursor = db_connection.cursor()

            # Check if a record with the same user_id already exists
            existing_record = db_cursor.execute(f'SELECT * FROM {table_name} WHERE user_id=?', (info.id,)).fetchone()

            if existing_record is None:
                if debug:
                    print("no record found, adding node to db")
                # No existing record, insert the new record
                db_cursor.execute(f'''
                    INSERT INTO {table_name} (user_id, long_name, short_name)
                    VALUES (?, ?, ?)
                ''', (info.id, info.long_name, info.short_name))
                db_connection.commit()

                # Fetch the new record
                new_record = db_cursor.execute(f'SELECT * FROM {table_name} WHERE user_id=?', (info.id,)).fetchone()

                # Display the new record in the nodeinfo_window widget
                message = f"{new_record[0]}, {new_record[1]}, {new_record[2]}"
                update_gui(message, text_widget=nodeinfo_window)
            else:
                # Check if long_name or short_name is different, update if necessary
                if existing_record[1] != info.long_name or existing_record[2] != info.short_name:
                    if debug:
                        print("updating existing record in db")
                    db_cursor.execute(f'''
                        UPDATE {table_name}
                        SET long_name=?, short_name=?
                        WHERE user_id=?
                    ''', (info.long_name, info.short_name, info.id))
                    db_connection.commit()

                    # Fetch the updated record
                    updated_record = db_cursor.execute(f'SELECT * FROM {table_name} WHERE user_id=?', (info.id,)).fetchone()

                    # Display the updated record in the nodeinfo_window widget
                    message = f"{updated_record[0]}, {updated_record[1]}, {updated_record[2]}"
                    update_gui(message, text_widget=nodeinfo_window)

    except sqlite3.Error as e:
        print(f"SQLite error in maybe_store_nodeinfo_in_db: {e}")

    finally:
        db_connection.close()


def maybe_store_position_in_db(node_id, position, rssi=None):
    """Save position if we have no position for this node_id or the timestamp is newer than the record we have stored."""

    # Must have at least a lat/lon
    if position.latitude_i != 0 and position.longitude_i != 0:

        rssi_string = ", RSSI: " + str(rssi) if rssi else ""
        if preferences.print_position_report:
            print("From: " + get_name_by_id("short", node_id) +
                ", lat: " + str(round(position.latitude_i * 1e-7, 7)) +
                ", lon: " + str(round(position.longitude_i * 1e-7, 7)) +
                ", alt: " + str(position.altitude) +
                ", PDOP: " + str(position.PDOP) +
                ", speed: " + str(position.ground_speed) +
                ", track: " + str(position.ground_track) +
                ", sats: " + str(position.sats_in_view) +
                rssi_string)

        # Convert from integer lat/lon format to decimal format.
        latitude = position.latitude_i * 1e-7
        longitude = position.longitude_i * 1e-7

        # Get the best timestamp we can, starting with local time.
        timestamp = time.gmtime()
        # Then, try the timestamp from the position protobuf.
        if position.timestamp > 0:
            timestamp = time.gmtime(position.timestamp)
        # Then, try the time from the position protobuf.
        if position.time > 0:
            timestamp = time.gmtime(position.time)
        # Convert timestamp to datetime for database use
        timestamp = datetime.fromtimestamp(mktime(timestamp))

        table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_positions"

        try:
            with sqlite3.connect(db_file_path) as db_connection:
                db_cursor = db_connection.cursor()

                # Check for an existing entry for the timestamp; this indicates a position that has bounced around the mesh.
                existing_record = db_cursor.execute(f'SELECT * FROM {table_name} WHERE node_id=?', (node_id,)).fetchone()

                # Insert a new record if none exists yet.
                if existing_record is None:
                    db_cursor.execute(f'''
                        INSERT INTO {table_name} (node_id, short_name, timestamp, latitude, longitude)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (node_id, get_name_by_id("short", node_id), timestamp, latitude, longitude))
                    db_connection.commit()
                    return

                if timestamp > datetime.strptime(existing_record[2], "%Y-%m-%d %H:%M:%S"):
                    db_cursor.execute(f'''
                        UPDATE {table_name}
                        SET short_name=?, timestamp=?, latitude=?, longitude=?
                        WHERE node_id=?
                    ''', (get_name_by_id("short", node_id), timestamp, latitude, longitude, node_id))
                    db_connection.commit()
                else:
                    if debug:
                        print("Rejecting old position record")

        except sqlite3.Error as e:
            print(f"SQLite error in maybe_store_position_in_db: {e}")

        finally:
            db_connection.close()


def insert_message_to_db(time, sender_short_name, text_payload, message_id, is_encrypted):
    """Save a meshtastic message to sqlite storage."""

    if debug:
        print("insert_message_to_db")

    table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_messages"

    try:
        with sqlite3.connect(db_file_path) as db_connection:
            db_cursor = db_connection.cursor()

            # Strip newline characters and insert the message into the messages table
            formatted_message = text_payload.strip()
            db_cursor.execute(f'INSERT INTO {table_name} (timestamp, sender, content, message_id, is_encrypted) VALUES (?,?,?,?,?)',
                              (time, sender_short_name, formatted_message, message_id, is_encrypted))
            db_connection.commit()

    except sqlite3.Error as e:
        print(f"SQLite error in insert_message_to_db: {e}")

    finally:
        db_connection.close()


def load_message_history_from_db():
    """Load previously stored messages from sqlite and display them."""

    if debug:
        print("load_message_history_from_db")

    table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_messages"

    try:
        with sqlite3.connect(db_file_path) as db_connection:
            db_cursor = db_connection.cursor()

            # Fetch all messages from the database
            messages = db_cursor.execute(f'SELECT timestamp, sender, content, is_encrypted FROM {table_name}').fetchall()

            message_history.config(state=tk.NORMAL)
            message_history.delete('1.0', tk.END)

            # Display each message in the message_history widget
            for message in messages:
                timestamp = format_time(message[0])
                if message[3] == 1:
                    the_message = f"{timestamp} {encrypted_emoji}{message[1]}: {message[2]}\n"
                else:
                    the_message = f"{timestamp} {message[1]}: {message[2]}\n"
                message_history.insert(tk.END, the_message)

            message_history.config(state=tk.DISABLED)

    except sqlite3.Error as e:
        print(f"SQLite error in load_message_history_from_db: {e}")

    finally:
        db_connection.close()


def erase_nodedb():
    """Erase all stored nodeinfo in sqlite and on display in the gui."""

    if debug:
        print("erase_nodedb")

    table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_nodeinfo"

    confirmed = tkinter.messagebox.askyesno("Confirmation", f"Are you sure you want to erase the database: {db_file_path} for channel {channel}?")

    if confirmed:
        try:
            with sqlite3.connect(db_file_path) as db_connection:
                db_cursor = db_connection.cursor()

                # Clear all records from the database
                db_cursor.execute(f'DELETE FROM {table_name}')
                db_connection.commit()

        except sqlite3.Error as e:
            print(f"SQLite error in erase_nodedb: {e}")

        finally:
            db_connection.close()

            # Clear the display
            nodeinfo_window.config(state=tk.NORMAL)
            nodeinfo_window.delete('1.0', tk.END)
            nodeinfo_window.config(state=tk.DISABLED)
            update_gui(f"{format_time(current_time())} >>> Node database for channel {channel} erased successfully.", tag="info")
    else:
        update_gui(f"{format_time(current_time())} >>> Node database erase for channel {channel} cancelled.", tag="info")



def erase_messagedb():
    """Erase all stored messages in sqlite and on display in the gui."""

    if debug:
        print("erase_messagedb")

    table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_messages"

    confirmed = tkinter.messagebox.askyesno("Confirmation", f"Are you sure you want to erase the message history of: {db_file_path} for channel {channel}?")

    if confirmed:
        try:
            with sqlite3.connect(db_file_path) as db_connection:
                db_cursor = db_connection.cursor()

                # Clear all records from the database
                db_cursor.execute(f'DELETE FROM {table_name}')
                db_connection.commit()

        except sqlite3.Error as e:
            print(f"SQLite error in erase_messagedb: {e}")

        finally:
            db_connection.close()

            # Clear the display
            message_history.config(state=tk.NORMAL)
            message_history.delete('1.0', tk.END)
            message_history.config(state=tk.DISABLED)
            update_gui(f"{format_time(current_time())} >>> Message history for channel {channel} erased successfully.", tag="info")
    else:
        update_gui(f"{format_time(current_time())} >>> Message history erase for channel {channel} cancelled.", tag="info")



def get_name_by_id(name_type: str, user_id: str) -> str:
    """See if we have a (long or short, as specified by "name_type") name for the given user_id."""

    # Convert the user_id to hex and prepend '!'
    hex_user_id: str = '!%08x' % user_id

    try:
        table_name = sanitize_string(mqtt_broker) + "_" + sanitize_string(root_topic) + sanitize_string(channel) + "_nodeinfo"
        with sqlite3.connect(db_file_path) as db_connection:
            db_cursor = db_connection.cursor()

            # Fetch the name based on the hex user ID
            if name_type == "long":
                result = db_cursor.execute(f'SELECT long_name FROM {table_name} WHERE user_id=?', (hex_user_id,)).fetchone()
            if name_type == "short":
                result = db_cursor.execute(f'SELECT short_name FROM {table_name} WHERE user_id=?', (hex_user_id,)).fetchone()

            if result:
                if debug:
                    print("found user in db: " + str(hex_user_id))
                return result[0]
            # If we don't find a user id in the db, ask for an id
            else:
                if user_id != BROADCAST_NUM:
                    if debug:
                        print("didn't find user in db: " + str(hex_user_id))
                    send_node_info(user_id, want_response=True)  # DM unknown user a nodeinfo with want_response
                return f"Unknown User ({hex_user_id})"

    except sqlite3.Error as e:
        print(f"SQLite error in get_name_by_id: {e}")

    finally:
        db_connection.close()

    return f"Unknown User ({hex_user_id})"