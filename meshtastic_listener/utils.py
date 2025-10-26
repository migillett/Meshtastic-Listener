import logging
import math
from os import environ

from .data_structures import SystemResources

import psutil

logger = logging.getLogger(__name__)


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

def system_stats() -> SystemResources:
    """
    Gather system resource usage statistics.
    """
    stats = SystemResources(
        cpuUsagePercent=round(psutil.cpu_percent(interval=None), 1),
        memoryUsagePercent=round(psutil.virtual_memory().percent, 1),
        diskUsagePercent=round(psutil.disk_usage('/').percent, 1)
    )
    logger.debug(f"System Resource Statistics: {stats.model_dump()}")
    return stats
