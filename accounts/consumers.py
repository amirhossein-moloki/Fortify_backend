import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from .models import User
from contacts.models import Contact

class PresenceConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']
        if self.user.is_anonymous:
            await self.close()
            return

        # Add user to their own group to receive updates
        await self.channel_layer.group_add(f"user_{self.user.id}", self.channel_name)
        await self.accept()

        # Set status to online and broadcast to contacts
        await self.set_user_online_status(True)
        await self.broadcast_status(online=True)

    async def disconnect(self, close_code):
        if self.user.is_anonymous:
            return

        # Set status to offline and broadcast to contacts
        await self.set_user_online_status(False)
        await self.broadcast_status(online=False)

        # Remove user from their group
        await self.channel_layer.group_discard(f"user_{self.user.id}", self.channel_name)

    async def broadcast_status(self, online):
        """ Broadcasts the user's status to their contacts. """
        contacts = await self.get_user_contacts()
        last_seen_iso = self.user.last_seen.isoformat() if self.user.last_seen else None

        for contact_user in contacts:
            await self.channel_layer.group_send(
                f"user_{contact_user.id}",
                {
                    "type": "presence_update",
                    "payload": {
                        "user_id": self.user.id,
                        "username": self.user.username,
                        "online": online,
                        "last_seen": last_seen_iso,
                    }
                },
            )

    async def presence_update(self, event):
        """ Handler to send presence updates to the client. """
        await self.send(text_data=json.dumps(event['payload']))

    @database_sync_to_async
    def set_user_online_status(self, online):
        # Update user instance in memory
        self.user.is_online = online
        if not online:
            self.user.last_seen = timezone.now()

        # Save to database
        User.objects.filter(pk=self.user.pk).update(
            is_online=online,
            last_seen=self.user.last_seen if not online else None
        )


    @database_sync_to_async
    def get_user_contacts(self):
        """
        Fetches a list of users who are contacts with the current user
        (where the relationship is accepted).
        """
        # Find users who have this user as a contact
        user_contacts = Contact.objects.filter(contact=self.user, status='accepted').select_related('user').values_list('user__id', flat=True)
        # Find contacts of this user
        contacts_of_user = Contact.objects.filter(user=self.user, status='accepted').select_related('contact').values_list('contact__id', flat=True)

        contact_ids = set(user_contacts).union(set(contacts_of_user))

        return list(User.objects.filter(id__in=contact_ids))
