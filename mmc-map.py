import sqlite3
import folium
import re
from statistics import mean

mqtt_broker = 'mqtt.meshtastic.org'
channel = 'LongFast'

def sanitize_string(input_str):
    # Check if the string starts with a letter (a-z, A-Z) or an underscore (_)
    if not re.match(r'^[a-zA-Z_]', input_str):
        # If not, add "_"
        input_str = '_' + input_str

    # Replace special characters with underscores (for database tables)
    sanitized_str = re.sub(r'[^a-zA-Z0-9_]', '_', input_str)
    return sanitized_str

table = sanitize_string(mqtt_broker) + "_" + sanitize_string(channel) + "_positions"
# Connect to SQLite database
conn = sqlite3.connect('mmc.db')
cursor = conn.cursor()

# Fetch latitude, longitude, and short_name data from the database
cursor.execute(f'SELECT latitude, longitude, short_name FROM {table};')
data = cursor.fetchall()

# Calculate the mean of latitude and longitude
mean_lat = mean(row[0] for row in data)
mean_lon = mean(row[1] for row in data)

# Create a Folium map centered at the mean location
my_map = folium.Map(location=[mean_lat, mean_lon], zoom_start=3)

# Add markers to the map based on the database data
for lat, lon, short_name in data:
    # Add labels using the short_name column
    label = short_name
    icon = folium.Icon(color='blue', icon='tower-broadcast', prefix='fa')
    folium.Marker([lat, lon], popup=label, icon=icon).add_to(my_map)

# Save the map as an HTML file
my_map.save('mmc-map.html')