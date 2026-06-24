from dataclasses import dataclass
from typing import List
import sys


@dataclass
class RoutingTableRow:
    iface: str
    dst: hex
    gateway: str
    metric: int
    mask: hex
    is_default_gateway: bool = False


ROUTING_TABLE_PATH = "/proc/net/route"
EMPTY_ROUTE = RoutingTableRow(None, None, None, None, None)


def get_routing_table_content() -> str:
    with open(ROUTING_TABLE_PATH, "r") as f:
        return f.read()
    
def parse_routing_table_content(content: str) -> RoutingTableRow:
    routing_table: List[RoutingTableRow] = []
    content_split_into_arr = content.split('\n')
    if len(content_split_into_arr) < 1:
        raise ValueError("Problem reading from the table")
    content_split_into_arr = content_split_into_arr[:-1]
    if len(content_split_into_arr) <= 1:
        raise ValueError("Routing table is empty")
    rows = content_split_into_arr[1:]
    for row in rows:
        entities = [entity for entity in row.split("\t")]
        routing_table.append(RoutingTableRow(iface=entities[0], 
                                             dst=int(entities[1], 16), 
                                             gateway=entities[2], 
                                             metric=int(entities[6]), 
                                             mask=int(entities[7], 16),
                            )
        )
    return routing_table

def best_route(routing_table: List[RoutingTableRow], target_ip: hex) -> RoutingTableRow:
    default_gateway = routing_table.pop(0) #Note we assume only one basic default gateway
    best_route = EMPTY_ROUTE
    best_metric = sys.maxsize
    max_subnet_mask = 00000000
    for route in routing_table:
        if route.mask >= max_subnet_mask:
            if (route.mask & route.dst) == (target_ip & route.mask):
                if route.metric <= best_metric:
                    best_route = route

    if best_route == EMPTY_ROUTE:
        default_gateway.is_default_gateway = True
        return default_gateway
    return best_route


# Example code
# import ipaddress
# ip_addr_in_hex = int(ipaddress.IPv4Address("172.27.47.1"))
# print(ip_addr_in_hex)
# print(best_route(parse_routing_table_content(get_routing_table_content()), ip_addr_in_hex))