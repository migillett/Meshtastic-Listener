from typing import Annotated

from meshtastic_listener.api.db_session import get_db_instance
from meshtastic_listener.listener_db.listener_db import ListenerDb, ItemNotFound
from meshtastic_listener.api.api_types import (
    NotificationRequest,
    PendingNotificationsResponse
)

from fastapi import APIRouter, Depends, HTTPException, status

router = APIRouter(
    prefix="/notifications",
    tags=["Notifications"],
    responses={404: {"description": "Not found"}},
)


@router.post('/', status_code=status.HTTP_202_ACCEPTED)
async def post_notification(
    notification: NotificationRequest,
    db: Annotated[ListenerDb, Depends(get_db_instance)]
) -> None:
    """
    Post an outgoing notification to a node.
    """
    db.insert_notification(
        to_id=notification.nodeNum,
        message=notification.message,
    )

@router.get('/{node_num}', status_code=status.HTTP_202_ACCEPTED)
async def get_notifications(
    node_num: int,
    db: Annotated[ListenerDb, Depends(get_db_instance)]
) -> list[PendingNotificationsResponse]:
    """
    Get all notifications for a node.
    """
    notifications = db.get_pending_notifications(node_num)
    if notifications is None:
        raise HTTPException(
            status_code=status.HTTP_204_NO_CONTENT,
            detail=f"No notifications found for node {node_num}"
        )
    return [
        PendingNotificationsResponse(**notification.__dict__)
        for notification in notifications
    ]

@router.patch('/{notification_id}', status_code=status.HTTP_200_OK)
async def increment_notification_attempts(
    notification_id: int,
    notif_tx_id: int,
    db: Annotated[ListenerDb, Depends(get_db_instance)]
) -> None:
    """
    Increment the attempts of a notification.
    """
    try:
        db.increment_notification_attempts(
            notification_id=notification_id,
            notif_tx_id=notif_tx_id
        )
    except ItemNotFound as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )

@router.patch('/{notification_id}', status_code=status.HTTP_202_ACCEPTED)
async def mark_notification_as_received(
    notification_id: int,
    db: Annotated[ListenerDb, Depends(get_db_instance)]
) -> None:
    """
    Mark a notification as received.
    """
    try:
        db.mark_notification_received(notification_id)
    except ItemNotFound as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
