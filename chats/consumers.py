import json
from urllib.parse import parse_qs
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from .models import Message, Attachment, Chat, Poll, PollOption, PollVote, SearchableMessage
from contacts.models import Block
from calls.models import Call
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed
from encryption.utils import Encryptor, get_or_create_shared_key
import base64
from io import BytesIO
from django.core.files.base import ContentFile
from django.utils import timezone

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.chat_id = self.scope['url_route']['kwargs']['chat_id']
        self.group_name = f"chat_{self.chat_id}"
        self.user = self.scope['user']

        if self.user.is_anonymous:
            await self.close()
            return

        try:
            chat = await database_sync_to_async(Chat.objects.get)(id=self.chat_id)
            participants = await database_sync_to_async(list)(chat.participants.all())
            other_user = None
            for p in participants:
                if p != self.user:
                    other_user = p
                    break

            if other_user:
                shared_key_str = await database_sync_to_async(get_or_create_shared_key)(self.user, other_user)
                shared_key = base64.b64decode(shared_key_str)
                self.encryptor = Encryptor(shared_key)

            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()

            messages = await self.get_messages()

            for message in messages:
                sender_name = await self.get_sender_username(message)
                sender_profile_picture = await self.get_sender_profile_picture(message)
                sender_bio = await self.get_sender_bio(message)

                decrypted_content = self.encryptor.decrypt(base64.b64decode(message.content))

                await self.send(text_data=json.dumps({
                    'message': decrypted_content,
                    'sender': sender_name,
                    'sender_profile_picture': sender_profile_picture,
                    'sender_bio': sender_bio,
                    'timestamp': message.timestamp.isoformat(),
                    'read_by': [user.username for user in await database_sync_to_async(list)(message.read_by.all())],
                    'is_edited': message.is_edited,
                    'is_deleted': message.is_deleted,
                    'action': 'send',
                    'message_id': message.id,
                    'file': None,
                }))

        except Exception:
            await self.close()

    async def receive(self, text_data):
        data = json.loads(text_data)
        action = data.get('action')

        if action == 'send':
            sender = self.scope['user']
            chat = await database_sync_to_async(Chat.objects.get)(id=self.chat_id)
            participants = await database_sync_to_async(list)(chat.participants.all())

            for participant in participants:
                if participant != sender:
                    is_blocked = await self.is_blocked(sender, participant)
                    if is_blocked:
                        await self.send(text_data=json.dumps({
                            'error': 'You cannot send messages to this user.'
                        }))
                        return

            message_content = data.get('message')
            searchable_text = data.get('searchable_text', message_content) # Fallback for older clients
            file = data.get('file')
            reply_to_id = data.get('reply_to')

            encrypted_content = self.encryptor.encrypt(message_content)
            message = await self.save_message(sender, encrypted_content, searchable_text, reply_to_id)

            sender_name = sender.username
            sender_profile_picture = sender.profile_picture.url if sender.profile_picture else None
            sender_bio = sender.bio if sender.bio else ""

            if file:
                file_content = base64.b64decode(file['content'])
                input_file = BytesIO(file_content)
                output_file = BytesIO()
                self.encryptor.encrypt_file(input_file, output_file)
                output_file.seek(0)

                encrypted_file = ContentFile(output_file.read(), name=file['name'])

                attachment = await self.save_attachment(message, encrypted_file, file['name'], file['type'], len(file_content), file.get('attachment_type', 'file'))
                file_data = {
                    'file_name': attachment.file_name,
                    'file_type': attachment.file_type,
                    'file_size': attachment.file_size,
                    'type': attachment.type,
                }
            else:
                file_data = None

            await self.channel_layer.group_send(
                self.group_name,
                {
                    'type': 'chat_message',
                    'message': base64.b64encode(message.content).decode(),
                    'sender': sender_name,
                    'sender_profile_picture': sender_profile_picture,
                    'sender_bio': sender_bio,
                    'timestamp': message.timestamp.isoformat(),
                    'read_by': [user.username for user in await database_sync_to_async(list)(message.read_by.all())],
                    'is_edited': message.is_edited,
                    'is_deleted': message.is_deleted,
                    'action': 'send',
                    'message_id': message.id,
                    'file': file_data,
                    'reply_to': reply_to_id,
                }
            )

        elif action == 'edit':
            message_id = data.get('message_id')
            new_content = data.get('new_message')
            sender = self.scope['user']

            message = await self.edit_message(message_id, new_content)

            await self.channel_layer.group_send(
                self.group_name,
                {
                    'type': 'chat_message',
                    'message': message.content,
                    'sender': sender.username,
                    'sender_profile_picture': sender.profile_picture.url if sender.profile_picture else None,
                    'sender_bio': sender.bio if sender.bio else "",
                    'timestamp': message.timestamp.isoformat(),
                    'read_by': [user.username for user in await database_sync_to_async(list)(message.read_by.all())],
                    'is_edited': message.is_edited,
                    'is_deleted': message.is_deleted,
                    'action': 'edit',
                    'message_id': message.id,
                }
            )

        elif action == 'delete':
            message_.id = data.get('message_id')
            sender = self.scope['user']

            await self.delete_message(message_id)

            await self.channel_layer.group_send(
                self.group_name,
                {
                    'type': 'chat_message',
                    'message_id': message_id,
                    'action': 'delete',
                    'sender': sender.username,
                }
            )

        elif action == 'read':
            message_id = data.get('message_id')
            await self.mark_as_read(message_id)

            await self.channel_layer.group_send(
                self.group_name,
                {
                    'type': 'chat_message',
                    'message_id': message_id,
                    'action': 'read',
                    'read_by': [user.username for user in
                                await database_sync_to_async(list)((await self.get_message_read_by(message_id)))],
                    'sender': self.scope['user'].username,
                }
            )

        elif action == 'typing':
            await self.channel_layer.group_send(
                self.group_name,
                {
                    'type': 'typing',
                    'user': self.scope['user'].username
                }
            )

        elif action == 'send_poll':
            question = data.get('question')
            options = data.get('options', [])

            if not question or not options or len(options) < 2:
                await self.send(text_data=json.dumps({
                    'error': 'A poll must have a question and at least two options.'
                }))
                return

            poll = await self.create_poll(question, options)
            message = await self.save_message(self.scope['user'], b'', searchable_text=None, poll=poll)

            from .serializers import WebsocketMessageSerializer

            @database_sync_to_async
            def get_serialized_message(msg):
                return WebsocketMessageSerializer(msg).data

            serialized_message = await get_serialized_message(message)

            await self.channel_layer.group_send(
                self.group_name,
                {
                    'type': 'chat_message',
                    'message': serialized_message,
                }
            )
        elif action == 'initiate_call':
            await self.initiate_call(data)

    async def chat_message(self, event):
        # This handler now needs to be able to handle both regular messages and full serialized message objects
        message_data = event.get('message')
        if isinstance(message_data, dict): # It's a poll or other special message
            await self.send(text_data=json.dumps(message_data))
            return

        message_id = event.get('message_id')
        delivered_at = await self.set_message_delivered(message_id)

        message_content = event.get('message')
        if not message_content:
            return

        decrypted_content = self.encryptor.decrypt(base64.b64decode(message_content))

        sender_name = event.get('sender')
        sender_profile_picture = event.get('sender_profile_picture')
        sender_bio = event.get('sender_bio')
        timestamp = event.get('timestamp')
        read_by = event.get('read_by')
        is_edited = event.get('is_edited')
        is_deleted = event.get('is_deleted')
        action = event.get('action')
        file_data = event.get('file')
        reply_to = event.get('reply_to')

        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'message': decrypted_content,
            'reply_to': reply_to,
            'delivered_at': delivered_at.isoformat() if delivered_at else None,
            'sender': sender_name,
            'sender_profile_picture': sender_profile_picture,
            'sender_bio': sender_bio,
            'timestamp': timestamp,
            'read_by': read_by,
            'is_edited': is_edited,
            'is_deleted': is_deleted,
            'action': action,
            'message_id': message_id,
            'file': file_data,
        }))

    async def typing(self, event):
        await self.send(text_data=json.dumps({
            'type': 'typing',
            'user': event['user']
        }))

    async def reaction_add(self, event):
        await self.send(text_data=json.dumps({
            'type': 'reaction_add',
            'reaction': event['reaction']
        }))

    async def reaction_remove(self, event):
        await self.send(text_data=json.dumps({
            'type': 'reaction_remove',
            'reaction_id': event['reaction_id'],
            'message_id': event['message_id']
        }))

    async def pin_message_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'pin_message_update',
            'chat': event['chat']
        }))

    async def poll_vote_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'poll_vote_update',
            'poll': event['poll']
        }))

    @database_sync_to_async
    def create_poll(self, question, options):
        poll = Poll.objects.create(question=question)
        for option_text in options:
            PollOption.objects.create(poll=poll, text=option_text)
        return poll

    @database_sync_to_async
    def is_blocked(self, user1, user2):
        return Block.objects.filter(blocker=user1, blocked=user2).exists() or \
               Block.objects.filter(blocker=user2, blocked=user1).exists()

    @database_sync_to_async
    def set_message_delivered(self, message_id):
        try:
            message = Message.objects.get(id=message_id)
            if not message.delivered_at:
                message.delivered_at = timezone.now()
                message.save()
            return message.delivered_at
        except Message.DoesNotExist:
            return None

    @database_sync_to_async
    def save_message(self, sender, content, searchable_text, reply_to_id=None, poll=None):
        reply_to = None
        if reply_to_id:
            try:
                reply_to = Message.objects.get(id=reply_to_id)
            except Message.DoesNotExist:
                pass

        message = Message.objects.create(sender=sender, content=content, chat_id=self.chat_id, reply_to=reply_to, poll=poll)
        message.is_read = True
        message.read_by.add(sender)
        message.save()

        # Create the searchable version
        if searchable_text and not poll: # Don't save searchable content for polls
            SearchableMessage.objects.create(
                message=message,
                user=sender,
                content=searchable_text
            )

        return message

    @database_sync_to_async
    def save_attachment(self, message, file, file_name, file_type, file_size, attachment_type='file'):
        attachment = Attachment.objects.create(
            message=message,
            file=file,
            file_name=file_name,
            file_type=file_type,
            file_size=file_size,
            type=attachment_type
        )
        return attachment

    @database_sync_to_async
    def edit_message(self, message_id, new_content):
        message = Message.objects.get(id=message_id)
        message.content = new_content
        message.is_edited = True
        message.save()
        return message

    @database_sync_to_async
    def delete_message(self, message_id):
        message = Message.objects.get(id=message_id)
        message.delete()

    @database_sync_to_async
    def mark_as_read(self, message_id):
        message = Message.objects.get(id=message_id)
        if self.scope['user'] not in message.read_by.all():
            message.is_read = True
            message.read_by.add(self.scope['user'])
            message.save()

    @database_sync_to_async
    def get_messages(self):
        return list(Message.objects.filter(chat=self.chat_id).order_by('timestamp'))

    @database_sync_to_async
    def get_message_read_by(self, message_id):
        message = Message.objects.get(id=message_id)
        return message.read_by.all()

    @database_sync_to_async
    def get_sender_username(self, message):
        return message.sender.username

    @database_sync_to_async
    def get_sender_profile_picture(self, message):
        return message.sender.profile_picture.url if message.sender.profile_picture else None

    @database_sync_to_async
    def get_sender_bio(self, message):
        return message.sender.bio if message.sender.bio else ""

    async def initiate_call(self, data):
        chat_id = data.get('chat_id')
        if not chat_id:
            return

        chat = await self.get_chat(chat_id)
        if not chat or chat.chat_type != 'direct':
            # For now, only support direct calls
            return

        participants = await database_sync_to_async(list)(chat.participants.all())
        callee = next((p for p in participants if p != self.user), None)

        if not callee:
            return

        caller = self.user
        call = await self.create_call(caller, callee)

        # Notify the callee via the CallConsumer's channel
        await self.channel_layer.group_send(
            f"user_{callee.id}",
            {
                'type': 'incoming_call',
                'call_id': call.id,
                'caller_id': caller.id,
                'caller_username': caller.username,
            }
        )

    @database_sync_to_async
    def get_chat(self, chat_id):
        try:
            return Chat.objects.get(id=chat_id)
        except Chat.DoesNotExist:
            return None

    @database_sync_to_async
    def create_call(self, caller, callee):
        return Call.objects.create(caller=caller, callee=callee, status='ringing')
