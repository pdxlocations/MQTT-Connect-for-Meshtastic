from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from meshtastic.protobuf import mesh_pb2
import base64
from preferences import print_message_packet, debug
from helper_functions import generate_hash

def decode_encrypted(mp, key):
    """Decrypt a meshtastic message."""

    try:
        # Convert key to bytes
        key_bytes = base64.b64decode(key.encode('ascii'))

        nonce_packet_id = getattr(mp, "id").to_bytes(8, "little")
        nonce_from_node = getattr(mp, "from").to_bytes(8, "little")

        # Put both parts into a single byte array.
        nonce = nonce_packet_id + nonce_from_node

        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(getattr(mp, "encrypted")) + decryptor.finalize()

        data = mesh_pb2.Data()
        data.ParseFromString(decrypted_bytes)
        mp.decoded.CopyFrom(data)

    except Exception as e:
        if print_message_packet:
            print(f"failed to decrypt: \n{mp}")
        if debug:
            print(f"*** Decryption failed: {str(e)}")

def encrypt_message(channel, key, mesh_packet, encoded_message, node_number):
    """Encrypt a message."""
    if debug:
        print("encrypt_message")

    if key == "AQ==":
        key = "1PG7OiApB1nwvP+rz05pAQ=="

    mesh_packet.channel = generate_hash(channel, key)
    key_bytes = base64.b64decode(key.encode('ascii'))

    # print (f"id = {mesh_packet.id}")
    nonce_packet_id = mesh_packet.id.to_bytes(8, "little")
    nonce_from_node = node_number.to_bytes(8, "little")
    # Put both parts into a single byte array.
    nonce = nonce_packet_id + nonce_from_node

    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(encoded_message.SerializeToString()) + encryptor.finalize()

    return encrypted_bytes