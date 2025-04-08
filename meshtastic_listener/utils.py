import logging
import math
from os import environ

logger = logging.getLogger(__name__)

EARTH_RADIUS = 6371000  # Radius of the Earth in meters

def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the distance between two GPS coordinates in meters.
    """
    # Convert latitude and longitude from degrees to radians
    lat1 = math.radians(lat1)
    lon1 = math.radians(lon1)
    lat2 = math.radians(lat2)
    lon2 = math.radians(lon2)

    # Calculate the change in latitude and longitude
    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1

    # Calculate the distance between the two points
    a = math.sin(delta_lat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return round(EARTH_RADIUS * c, 4)


def meters_to_miles(meters: float) -> float:
    """
    Convert meters to miles.
    """
    return round(meters / 1609.34, 2)


def coords_int_to_float(coordinate: int) -> float:
    """
    Convert an integer GPS coordinate to a float.
    """
    num_places = len(str(coordinate).replace('-', '')) - 2
    return round(coordinate / 10**(num_places), 7)


def load_node_env_var(env_var_name: str) -> list[int] | None:
    # node values can be integers or strings that start with "!"
    # all env vars are strings, so we need to check for both types
    # makes sure that the user-provided node_id is an integer and not a string
    node_ids = environ.get(env_var_name, None)
    if node_ids is None:
        return None
    nodes = node_ids.split(',')
    for node_id in nodes:
        if not node_id.isdigit() and not (isinstance(node_id, str) and node_id.startswith('!')):
            raise EnvironmentError(f"Invalid node_id: {node_id}. It must be an integer.")
    else:
        return [int(node_id) for node_id in nodes]

if __name__ == "__main__":
    # Example usage
    lat1, lon1 = 37.7749, -122.4194
    lat2, lon2 = 34.0522, -118.2437

    # verified from https://www.omnicalculator.com/other/latitude-longitude-distance
    distance = calculate_distance(lat1, lon1, lat2, lon2)
    print(f"The distance between the two points is {distance:.2f} meters.")
    assert round(distance, 0) == 559121, f'Expected 559121, got {int(distance)}'

    miles = meters_to_miles(distance)
    print(f"The distance between the two points is {miles:.2f} miles.")
    assert round(miles, 0) == 347, f'Expected 347, got {int(miles)}'
