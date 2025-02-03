import math

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
    return EARTH_RADIUS * c


def meters_to_miles(meters: float) -> float:
    """
    Convert meters to miles.
    """
    return meters / 1609.34


if __name__ == "__main__":
    # Example usage
    lat1 = 37.7749
    lon1 = -122.4194
    lat2 = 34.0522
    lon2 = -118.2437

    # verified from https://www.omnicalculator.com/other/latitude-longitude-distance
    distance = calculate_distance(lat1, lon1, lat2, lon2)
    print(f"The distance between the two points is {distance:.2f} meters.")
    assert round(distance, 0) == 559121, f'Expected 559121, got {int(distance)}'

    miles = meters_to_miles(distance)
    print(f"The distance between the two points is {miles:.2f} miles.")
    assert round(miles, 0) == 347, f'Expected 347, got {int(miles)}'
