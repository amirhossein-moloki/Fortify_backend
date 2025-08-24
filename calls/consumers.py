import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import Call
from django.contrib.auth import get_user_model

User = get_user_model()

class CallConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']
        if self.user.is_anonymous:
            await self.close()
        else:
            self.group_name = f"user_{self.user.id}"
            await self.channel_layer.group_add(
                self.group_name,
                self.channel_name
            )
            await self.accept()

    async def disconnect(self, close_code):
        if self.user.is_authenticated:
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )

    async def receive(self, text_data):
        data = json.loads(text_data)
        action = data.get('action')

        # We will add handlers for different actions here
        if action == 'start_call':
            await self.start_call(data)
        elif action == 'offer':
            await self.handle_offer(data)
        elif action == 'answer':
            await self.handle_answer(data)
        elif action == 'ice_candidate':
            await self.handle_ice_candidate(data)
        elif action == 'hang_up':
            await self.handle_hang_up(data)
        elif action == 'reject_call':
            await self.handle_reject_call(data)
        elif action == 'answer_call':
            await self.handle_answer_call(data)
        elif action == 'cancel_call':
            await self.handle_cancel_call(data)

    async def start_call(self, data):
        callee_id = data.get('callee_id')
        if not callee_id:
            return

        caller = self.user
        callee = await self.get_user(callee_id)

        if not callee:
            return

        call = await self.create_call(caller, callee)

        # Notify the callee
        await self.channel_layer.group_send(
            f"user_{callee.id}",
            {
                'type': 'incoming_call',
                'call_id': call.id,
                'caller_id': caller.id,
                'caller_username': caller.username,
            }
        )

    async def handle_offer(self, data):
        callee_id = data.get('callee_id')
        offer = data.get('offer')

        await self.channel_layer.group_send(
            f"user_{callee_id}",
            {
                'type': 'call_offer',
                'offer': offer,
                'caller_id': self.user.id,
            }
        )

    async def handle_answer(self, data):
        caller_id = data.get('caller_id')
        answer = data.get('answer')

        await self.channel_layer.group_send(
            f"user_{caller_id}",
            {
                'type': 'call_answer',
                'answer': answer,
                'callee_id': self.user.id,
            }
        )

    async def handle_ice_candidate(self, data):
        peer_id = data.get('peer_id')
        candidate = data.get('candidate')

        await self.channel_layer.group_send(
            f"user_{peer_id}",
            {
                'type': 'ice_candidate',
                'candidate': candidate,
                'sender_id': self.user.id,
            }
        )

    async def handle_hang_up(self, data):
        peer_id = data.get('peer_id')
        call_id = data.get('call_id')

        call = await self.get_call(call_id)
        if call:
            await self.end_call_db(call)

        await self.channel_layer.group_send(
            f"user_{peer_id}",
            {
                'type': 'call_hanged_up',
                'hanged_up_by': self.user.id
            }
        )

    # Handlers for channel layer events
    async def incoming_call(self, event):
        await self.send(text_data=json.dumps({
            'type': 'incoming_call',
            'call_id': event['call_id'],
            'caller_id': event['caller_id'],
            'caller_username': event['caller_username'],
        }))

    async def call_offer(self, event):
        await self.send(text_data=json.dumps({
            'type': 'call_offer',
            'offer': event['offer'],
            'caller_id': event['caller_id']
        }))

    async def call_answer(self, event):
        await self.send(text_data=json.dumps({
            'type': 'call_answer',
            'answer': event['answer'],
            'callee_id': event['callee_id']
        }))

    async def ice_candidate(self, event):
        await self.send(text_data=json.dumps({
            'type': 'ice_candidate',
            'candidate': event['candidate'],
            'sender_id': event['sender_id']
        }))

    async def call_hanged_up(self, event):
        await self.send(text_data=json.dumps({
            'type': 'call_hanged_up',
            'hanged_up_by': event['hanged_up_by']
        }))

    # Database methods
    @database_sync_to_async
    def get_user(self, user_id):
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

    @database_sync_to_async
    def create_call(self, caller, callee):
        return Call.objects.create(caller=caller, callee=callee, status='ringing')

    @database_sync_to_async
    def get_call(self, call_id):
        try:
            return Call.objects.get(id=call_id)
        except Call.DoesNotExist:
            return None

    @database_sync_to_async
    def end_call_db(self, call):
        call.end_call()

    async def handle_reject_call(self, data):
        call_id = data.get('call_id')
        caller_id = data.get('caller_id')
        call = await self.get_call(call_id)
        if call:
            await self.reject_call_db(call)

        await self.channel_layer.group_send(
            f"user_{caller_id}",
            {
                'type': 'call_rejected',
                'callee_id': self.user.id,
            }
        )

    async def handle_answer_call(self, data):
        call_id = data.get('call_id')
        caller_id = data.get('caller_id')
        call = await self.get_call(call_id)
        if call:
            await self.answer_call_db(call)

        await self.channel_layer.group_send(
            f"user_{caller_id}",
            {
                'type': 'call_answered',
                'callee_id': self.user.id,
            }
        )

    async def handle_cancel_call(self, data):
        call_id = data.get('call_id')
        callee_id = data.get('callee_id')
        call = await self.get_call(call_id)
        if call:
            await self.cancel_call_db(call)

        await self.channel_layer.group_send(
            f"user_{callee_id}",
            {
                'type': 'call_cancelled',
                'caller_id': self.user.id,
            }
        )

    # Channel layer event handlers
    async def call_rejected(self, event):
        await self.send(text_data=json.dumps(event))

    async def call_answered(self, event):
        await self.send(text_data=json.dumps(event))

    async def call_cancelled(self, event):
        await self.send(text_data=json.dumps(event))

    # DB methods
    @database_sync_to_async
    def reject_call_db(self, call):
        call.reject_call()

    @database_sync_to_async
    def answer_call_db(self, call):
        call.answer_call()

    @database_sync_to_async
    def cancel_call_db(self, call):
        call.cancel_call()
