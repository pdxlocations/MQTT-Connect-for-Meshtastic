import sqlite3
import folium
from statistics import mean

# Connect to SQLite database
conn = sqlite3.connect('mqtt.meshtastic.org_LongFast.db')
cursor = conn.cursor()

# Fetch latitude, longitude, and short_name data from the database
cursor.execute('SELECT latitude, longitude, short_name FROM positions;')
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