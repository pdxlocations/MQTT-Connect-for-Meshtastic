import time
from datetime import datetime
from typing import Optional
import string
import base64
import re
from meshtastic import BROADCAST_NUM
from preferences import debug

#################################
### Program Base Functions
def is_valid_hex(test_value: str, minchars: Optional[int], maxchars: int) -> bool:
    """Check if the provided string is valid hex.  Note that minchars and maxchars count INDIVIDUAL HEX LETTERS, inclusive.  Setting either to None means you don't care about that one."""

    if test_value.startswith('!'):
        test_value = test_value[1:]		#Ignore a leading exclamation point
    valid_hex_return: bool = all(c in string.hexdigits for c in test_value)
    if minchars is not None:
        valid_hex_return = valid_hex_return and (minchars <= len(test_value))
    if maxchars is not None:
        valid_hex_return = valid_hex_return and (len(test_value) <= maxchars)

    return valid_hex_return




def current_time() -> str:
    """Return the current time (as an integer number of seconds since the epoch) as a string."""

    current_time_str = str(int(time.time()))
    return current_time_str


def format_time(time_str: str) -> str:
    """Convert the time string (number of seconds since the epoch) back to a datetime object."""

    timestamp: int = int(time_str)
    time_dt: datetime = datetime.fromtimestamp(timestamp)

    # Get the current datetime for comparison
    now = datetime.now()

    # Check if the provided time is from today
    if time_dt.date() == now.date():
        # If it's today, format as "H:M am/pm"
        time_formatted = time_dt.strftime("%I:%M %p")
    else:
        # If it's not today, format as "DD/MM/YY H:M:S"
        time_formatted = time_dt.strftime("%d/%m/%y %H:%M:%S")

    return time_formatted


def xor_hash(data: bytes) -> int:
    """Return XOR hash of all bytes in the provided string."""

    result = 0
    for char in data:
        result ^= char
    return result


def generate_hash(name: str, key: str) -> int:
    """?"""

    replaced_key = key.replace('-', '+').replace('_', '/')
    key_bytes = base64.b64decode(replaced_key.encode('utf-8'))
    h_name = xor_hash(bytes(name, 'utf-8'))
    h_key = xor_hash(key_bytes)
    result: int = h_name ^ h_key
    return result





def sanitize_string(input_str: str) -> str:
    """Check if the string starts with a letter (a-z, A-Z) or an underscore (_), and replace all non-alpha/numeric/underscore characters with underscores."""

    if not re.match(r'^[a-zA-Z_]', input_str):
        # If not, add "_"
        input_str = '_' + input_str

    # Replace special characters with underscores (for database tables)
    sanitized_str: str = re.sub(r'[^a-zA-Z0-9_]', '_', input_str)
    return sanitized_str
