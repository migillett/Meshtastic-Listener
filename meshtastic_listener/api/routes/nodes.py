from typing import Annotated, Optional

from meshtastic_listener.api.db_session import get_db_instance
from meshtastic_listener.data_structures import NodeRoles
from meshtastic_listener.listener_db.listener_db import ListenerDb
from meshtastic_listener.api.api_types import (
    NodeDetailsResponse, AllNodesResponse
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='Node not found'
        )
    return node
