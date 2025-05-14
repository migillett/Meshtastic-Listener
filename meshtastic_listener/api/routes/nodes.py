from typing import Annotated, Optional

from meshtastic_listener.api.db_session import get_db_instance
from meshtastic_listener.data_structures import NodeRoles
from meshtastic_listener.listener_db.listener_db import ListenerDb, ItemNotFound
from meshtastic_listener.api.api_types import (
    NodeDetailsResponse,
    AllNodesResponse,
    PositionUpdateRequest
)

from fastapi import APIRouter, Depends, HTTPException, status

router = APIRouter(
    prefix="/nodes",
    tags=["Nodes"],
    responses={404: {"description": "Not found"}},
)


@router.get('/', response_model=AllNodesResponse)
async def get_all_nodes(
    page: int = 0,
    limit: int = 50,
    role: Optional[NodeRoles] = None,
    db: ListenerDb = Depends(get_db_instance)
) -> AllNodesResponse:
    """
    Get all nodes from the DB.
    :param page: The page number to return.
    :param limit: The number of nodes to return per page.
    :param role: Query nodes by their published role type.
    """
    nodes = db.get_nodes(role=role)
    start_index = page * limit
    end_index = start_index + limit
    return AllNodesResponse(
        total=len(nodes),
        start=start_index,
        page=page,
        nodes=[
            NodeDetailsResponse(**node.__dict__) for node in 
            nodes[start_index:end_index]
        ]
    )

@router.get('/{node_num}', response_model=NodeDetailsResponse)
async def get_specific_node(
    node_num: int,
    db: Annotated[ListenerDb, Depends(get_db_instance)]
) -> NodeDetailsResponse:
    """
    Get a specific node from the DB by node number.
    """
    node = db.get_node(node_num)
    if node is None:
        return {"error": "Node not found"}
    return node

@router.post('/', response_model=NodeDetailsResponse)
async def create_or_update_node(
    node: NodeDetailsResponse,
    db: Annotated[ListenerDb, Depends(get_db_instance)]
) -> NodeDetailsResponse:
    """
    Create a new Node in the DB. If the node already exists, it will be updated.
    """
    node = db.create_node(node)
    if node is None:
        return {"error": "Node already exists"}
    return node

@router.patch('/{node_num}/location', response_model=NodeDetailsResponse)
async def update_node_location(
    node_num: int,
    position: PositionUpdateRequest,
    db: Annotated[ListenerDb, Depends(get_db_instance)]
) -> NodeDetailsResponse:
    """
    Update the location of a node in the DB.
    """
    try:
        db.upsert_position(
            node_num=node_num,
            last_heard=position.timestamp,
            latitude=position.latitude,
            longitude=position.longitude,
            altitude=position.altitude,
            precision_bits=position.precisionBits,
        )
    except ItemNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_num} not found"
        )
