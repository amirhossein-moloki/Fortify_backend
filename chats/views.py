from .serializers import GetChatsSerializer, ReactionSerializer, MessageSerializer, PollSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import api_view
from .serializers import ChatSerializer
from rest_framework.exceptions import NotFound
from accounts.models import User
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Chat, Role, Message, Reaction, Poll, PollOption, PollVote
from contacts.models import Block
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied
from django.http import HttpResponse
from .models import Attachment
from encryption.utils import Encryptor, get_or_create_shared_key
from django.db.models import Count, Q, OuterRef, Subquery
import base64
from io import BytesIO
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

class CreateChatView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        chat_type = data.get('chat_type')  # نوع چت (direct, group, channel)
        user1 = request.user  # کاربر اول از توکن احراز هویت گرفته می‌شود
        user2_username = data.get('user2')  # یوزرنیم کاربر دوم (برای چت direct)

        # بررسی وجود کاربر دوم
        try:
            user2 = User.objects.get(username=user2_username)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_400_BAD_REQUEST)

        # بررسی وجود تصویر گروه
        group_image = None
        if chat_type == 'group' or chat_type == 'channel':
            group_image = request.FILES.get('group_image')  # دریافت تصویر گروه از درخواست

            if not group_image and chat_type in ['group', 'channel']:
                return Response({"error": "Group image is required."}, status=status.HTTP_400_BAD_REQUEST)

        # ساخت چت
        if chat_type == 'direct':
            # چک برای چت‌های دایرکت موجود
            existing_chat = Chat.objects.filter(
                chat_type='direct',
                participants=user1
            ).filter(participants=user2).first()

            if existing_chat:
                return Response(
                    {"error": "A direct chat between these users already exists."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # ایجاد چت جدید
            chat = Chat.objects.create(chat_type='direct')
            chat.participants.add(user1, user2)
            chat.group_admin.set([user1])
            chat.save()


        elif chat_type == 'group':
            # ایجاد چت گروهی
            group_name = data.get('group_name')
            max_participants = data.get('max_participants', 50)  # حداکثر تعداد اعضا

            if not group_name:
                return Response({"error": "Group name is required."}, status=status.HTTP_400_BAD_REQUEST)

            chat = Chat.objects.create(chat_type='group', group_name=group_name, max_participants=max_participants)
            chat.participants.add(user1, user2)  # اضافه کردن دو کاربر به چت
            chat.group_admin.set([user1])  # کاربر اول به عنوان ادمین

            # ذخیره تصویر گروه
            if group_image:
                chat.group_image = group_image  # ذخیره تصویر گروه

            chat.save()

            # نقش‌ها را برای اعضای گروه تنظیم می‌کنیم


        elif chat_type == 'channel':
            # ایجاد چت کانال
            group_name = data.get('group_name')

            if not group_name:
                return Response({"error": "Channel name is required."}, status=status.HTTP_400_BAD_REQUEST)

            chat = Chat.objects.create(chat_type='channel', group_name=group_name)
            chat.participants.add(user1, user2)  # اضافه کردن دو کاربر به چت
            chat.group_admin.set([user1])  # کاربر اول به عنوان ادمین

            # ذخیره تصویر گروه (برای کانال نیز)
            if group_image:
                chat.group_image = group_image  # ذخیره تصویر گروه

            chat.save()

        else:
            return Response({"error": "Invalid chat type."}, status=status.HTTP_400_BAD_REQUEST)

        # بازگرداندن اطلاعات چت جدید به همراه جزئیات آن
        serializer = ChatSerializer(chat, context={'request': request})
        return Response(serializer.data, status=status.HTTP_201_CREATED)




class UpdateChatView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, chat_id):
        """
        این ویو برای تغییر نام کانال یا گروه و یا عکس کانال استفاده می‌شود.
        """
        try:
            chat = Chat.objects.get(id=chat_id)
        except Chat.DoesNotExist:
            return Response({"error": "Chat not found."}, status=status.HTTP_404_NOT_FOUND)

        # بررسی اینکه آیا کاربر ادمین این چت است
        if request.user not in chat.group_admin.all():
            return Response({"error": "You are not the admin of this chat."}, status=status.HTTP_403_FORBIDDEN)

        # تغییرات مجاز
        group_name = request.data.get('group_name')
        group_image = request.data.get('group_image')  # فرض می‌کنیم که عکس کانال به صورت فایل ارسال می‌شود

        if group_name:
            chat.group_name = group_name

        if 'group_image' in request.FILES:
            chat.group_image = request.FILES['group_image']  # دریافت و ذخیره عکس گروه

        chat.save()

        serializer = ChatSerializer(chat)
        return Response(serializer.data, status=status.HTTP_200_OK)



class DeleteChatView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, chat_id):
        """
        این ویو برای حذف کانال یا گروه استفاده می‌شود.
        """
        try:
            chat = Chat.objects.get(id=chat_id)
        except Chat.DoesNotExist:
            return Response({"error": "Chat not found."}, status=status.HTTP_404_NOT_FOUND)

        # بررسی اینکه آیا کاربر ادمین این چت است
        if request.user not in chat.group_admin.all():
            return Response({"error": "You are not the admin of this chat."}, status=status.HTTP_403_FORBIDDEN)

        # حذف چت
        chat.delete()

        return Response({"message": "Chat deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


class AddUserToChatView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, chat_id):
        """
        این ویو برای اضافه کردن چندین کاربر به گروه یا کانال استفاده می‌شود.
        """
        try:
            chat = Chat.objects.get(id=chat_id)
        except Chat.DoesNotExist:
            return Response({"error": "Chat not found."}, status=status.HTTP_404_NOT_FOUND)

        # بررسی اینکه آیا کاربر ادمین این چت است
        if request.user not in chat.group_admin.all():
            return Response({"error": "You are not the admin of this chat."}, status=status.HTTP_403_FORBIDDEN)

        # دریافت یوزرنیم‌های کاربران که می‌خواهیم به چت اضافه کنیم
        usernames = request.data.get('usernames')
        if not usernames or not isinstance(usernames, list):
            return Response({"error": "Usernames must be provided as a list."}, status=status.HTTP_400_BAD_REQUEST)

        # اضافه کردن کاربران به چت
        new_users = []
        already_in_chat = []

        for username in usernames:
            try:
                new_user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response({"error": f"User {username} not found."}, status=status.HTTP_400_BAD_REQUEST)

            # بررسی اینکه آیا کاربر قبلاً عضو چت است یا نه
            if new_user in chat.participants.all():
                already_in_chat.append(username)
                continue

            # Check for blocking conflicts
            existing_participants = chat.participants.all()
            for participant in existing_participants:
                if Block.objects.filter(blocker=new_user, blocked=participant).exists() or \
                   Block.objects.filter(blocker=participant, blocked=new_user).exists():
                    return Response({"error": f"Cannot add {username} due to a block in place with an existing member."}, status=status.HTTP_400_BAD_REQUEST)

            chat.participants.add(new_user)
            new_users.append(new_user)

        chat.save()

        # پیام نهایی
        message = f"Users {', '.join([user.username for user in new_users])} added successfully."
        if already_in_chat:
            message += f" Users {', '.join(already_in_chat)} were already in the chat."

        return Response({"message": message}, status=status.HTTP_200_OK)



class RemoveUserFromChatView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, chat_id):
        """
        این ویو برای اخراج چندین کاربر از گروه یا کانال استفاده می‌شود.
        """
        try:
            chat = Chat.objects.get(id=chat_id)
        except Chat.DoesNotExist:
            return Response({"error": "Chat not found."}, status=status.HTTP_404_NOT_FOUND)

        # بررسی اینکه آیا کاربر ادمین این چت است
        if request.user not in chat.group_admin.all():
            return Response({"error": "You are not the admin of this chat."}, status=status.HTTP_403_FORBIDDEN)

        # دریافت یوزرنیم‌های کاربران که می‌خواهیم از چت اخراج کنیم
        usernames = request.data.get('usernames')
        if not usernames or not isinstance(usernames, list):
            return Response({"error": "Usernames must be provided as a list."}, status=status.HTTP_400_BAD_REQUEST)

        removed_users = []
        not_found_users = []
        not_in_chat_users = []

        for username in usernames:
            try:
                remove_user = User.objects.get(username=username)
            except User.DoesNotExist:
                not_found_users.append(username)
                continue

            # بررسی اینکه آیا کاربر عضو چت است
            if remove_user not in chat.participants.all():
                not_in_chat_users.append(username)
                continue

            chat.participants.remove(remove_user)
            removed_users.append(remove_user)

        chat.save()

        # بررسی پیام‌های خطا
        error_messages = []
        if not_found_users:
            error_messages.append(f"User(s) {', '.join(not_found_users)} not found.")
        if not_in_chat_users:
            error_messages.append(f"User(s) {', '.join(not_in_chat_users)} are not in the chat.")

        if error_messages:
            return Response({"error": " | ".join(error_messages)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"message": f"User(s) {', '.join([user.username for user in removed_users])} removed successfully."},
            status=status.HTTP_200_OK
        )

class LeaveChatView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, chat_id):
        """
        این ویو برای خروج کاربر از گروه یا کانال استفاده می‌شود.
        """
        try:
            chat = Chat.objects.get(id=chat_id)
        except Chat.DoesNotExist:
            return Response({"error": "Chat not found."}, status=status.HTTP_404_NOT_FOUND)

        # بررسی اینکه آیا کاربر عضو چت است
        if request.user not in chat.participants.all():
            return Response({"error": "You are not a participant in this chat."}, status=status.HTTP_403_FORBIDDEN)

        # حذف کاربر از چت
        chat.participants.remove(request.user)
        chat.save()

        return Response({"message": "You have successfully left the chat."}, status=status.HTTP_200_OK)




class GetUserChatsView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, *args, **kwargs):
        user = request.user

        last_message_subquery = Message.objects.filter(
            chat=OuterRef('pk'), is_deleted=False
        ).order_by('-timestamp').values('content')[:1]

        chats = Chat.objects.filter(participants=user).prefetch_related(
            'participants', 'group_admin'
        ).annotate(
            unread_count=Count('messages', filter=Q(messages__is_read=False) & ~Q(messages__read_by=user)),
            last_message_content=Subquery(last_message_subquery)
        )

        serializer = GetChatsSerializer(chats, many=True, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)


class SearchChatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('search', '')  # جستجو بر اساس نام چت
        chats = Chat.objects.filter(group_name__icontains=query, participants=request.user)

        serializer = GetChatsSerializer(chats, many=True, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
def get_chat_participants(request, chat_id):
    # ابتدا بررسی می‌کنیم که آیا کاربر درخواست را فرستاده در چت حضور دارد یا نه
    user = request.user
    try:
        chat = Chat.objects.get(id=chat_id)
    except Chat.DoesNotExist:
        raise NotFound('Chat not found')

    # بررسی اینکه آیا کاربر در لیست شرکت‌کنندگان چت وجود دارد
    if user not in chat.participants.all():
        raise PermissionDenied('You are not authorized to view this chat')

    # مقداردهی سریالایزر با ارسال context برای دسترسی به request
    serializer = ChatSerializer(chat, context={'request': request})
    return Response(serializer.data)

@api_view(['GET'])
def download_attachment(request, attachment_id):
    user = request.user
    try:
        attachment = Attachment.objects.get(id=attachment_id)
    except Attachment.DoesNotExist:
        raise NotFound('Attachment not found')

    chat = attachment.message.chat
    if user not in chat.participants.all():
        raise PermissionDenied('You are not authorized to view this attachment')

    other_user = chat.participants.exclude(id=user.id).first()
    if not other_user:
        raise PermissionDenied('Cannot determine the other user to create a shared key')

    shared_key_str = get_or_create_shared_key(user, other_user)
    shared_key = base64.b64decode(shared_key_str)
    encryptor = Encryptor(shared_key)

    encrypted_file = attachment.file
    encrypted_file.open('rb')

    output_file = BytesIO()
    encryptor.decrypt_file(encrypted_file, output_file)
    output_file.seek(0)

    encrypted_file.close()

    response = HttpResponse(output_file.getvalue(), content_type=attachment.file_type)
    response['Content-Disposition'] = f'attachment; filename="{attachment.file_name}"'
    return response


class ReactToMessageView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, message_id):
        emoji = request.data.get('emoji')
        if not emoji:
            return Response({"error": "Emoji is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            message = Message.objects.get(id=message_id)
        except Message.DoesNotExist:
            return Response({"error": "Message not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user not in message.chat.participants.all():
            return Response({"error": "You are not a participant in this chat."}, status=status.HTTP_403_FORBIDDEN)

        reaction, created = Reaction.objects.get_or_create(
            message=message,
            user=request.user,
            defaults={'emoji': emoji}
        )
        reaction.emoji = emoji
        reaction.save()


        serializer = ReactionSerializer(reaction)
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"chat_{message.chat.id}",
            {
                "type": "reaction_add",
                "reaction": serializer.data,
            },
        )

        if created:
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, message_id):
        emoji = request.data.get('emoji')
        if not emoji:
            return Response({"error": "Emoji is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            reaction = Reaction.objects.get(
                message_id=message_id,
                user=request.user,
                emoji=emoji
            )
            reaction_id = reaction.id
            message_chat_id = reaction.message.chat.id
            reaction.delete()

            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"chat_{message_chat_id}",
                {
                    "type": "reaction_remove",
                    "reaction_id": reaction_id,
                    "message_id": message_id,
                },
            )

            return Response(status=status.HTTP_204_NO_CONTENT)
        except Reaction.DoesNotExist:
            return Response({"error": "Reaction not found."}, status=status.HTTP_404_NOT_FOUND)


class PinMessageView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, chat_id, message_id):
        try:
            chat = Chat.objects.get(id=chat_id)
            message = Message.objects.get(id=message_id)
        except Chat.DoesNotExist:
            return Response({"error": "Chat not found."}, status=status.HTTP_404_NOT_FOUND)
        except Message.DoesNotExist:
            return Response({"error": "Message not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user not in chat.group_admin.all():
            return Response({"error": "You do not have permission to pin messages in this chat."}, status=status.HTTP_403_FORBIDDEN)

        if message.chat != chat:
            return Response({"error": "Message is not in this chat."}, status=status.HTTP_400_BAD_REQUEST)

        chat.pinned_message = message
        chat.save()

        serializer = ChatSerializer(chat, context={'request': request})

        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"chat_{chat_id}",
            {
                "type": "pin_message_update",
                "chat": serializer.data,
            },
        )

        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, chat_id, message_id):
        try:
            chat = Chat.objects.get(id=chat_id)
        except Chat.DoesNotExist:
            return Response({"error": "Chat not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user not in chat.group_admin.all():
            return Response({"error": "You do not have permission to unpin messages in this chat."}, status=status.HTTP_403_FORBIDDEN)

        if chat.pinned_message is None or chat.pinned_message.id != message_id:
            return Response({"error": "This message is not pinned."}, status=status.HTTP_400_BAD_REQUEST)

        chat.pinned_message = None
        chat.save()

        serializer = ChatSerializer(chat, context={'request': request})

        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"chat_{chat_id}",
            {
                "type": "pin_message_update",
                "chat": serializer.data,
            },
        )

        return Response(status=status.HTTP_204_NO_CONTENT)


class ForwardMessageView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, message_id):
        try:
            original_message = Message.objects.get(id=message_id)
        except Message.DoesNotExist:
            return Response({"error": "Message not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user not in original_message.chat.participants.all():
            return Response({"error": "You do not have permission to forward this message."}, status=status.HTTP_403_FORBIDDEN)

        chat_ids = request.data.get('chat_ids', [])
        if not chat_ids:
            return Response({"error": "No chat IDs provided."}, status=status.HTTP_400_BAD_REQUEST)

        forwarded_messages = []
        for chat_id in chat_ids:
            try:
                chat = Chat.objects.get(id=chat_id)
            except Chat.DoesNotExist:
                continue

            if request.user not in chat.participants.all():
                continue

            # Check for blocking conflicts
            is_blocked = False
            for participant in chat.participants.all():
                if Block.objects.filter(blocker=request.user, blocked=participant).exists() or \
                   Block.objects.filter(blocker=participant, blocked=request.user).exists():
                    is_blocked = True
                    break
            if is_blocked:
                continue

            new_message = Message.objects.create(
                chat=chat,
                sender=request.user,
                content=original_message.content,
                is_forwarded=True,
                forwarded_from=original_message.sender
            )
            forwarded_messages.append(new_message)

            # WebSocket event
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"chat_{chat_id}",
                {
                    'type': 'chat_message',
                    'message': base64.b64encode(new_message.content).decode(),
                    'sender': new_message.sender.username,
                    'sender_profile_picture': new_message.sender.profile_picture.url if new_message.sender.profile_picture else None,
                    'sender_bio': new_message.sender.bio if new_message.sender.bio else "",
                    'timestamp': new_message.timestamp.isoformat(),
                    'read_by': [],
                    'is_edited': new_message.is_edited,
                    'is_deleted': new_message.is_deleted,
                    'action': 'send',
                    'message_id': new_message.id,
                    'file': None, # Forwarding files is not supported in this version
                    'reply_to': None, # Forwarding replies is not supported in this version
                    'is_forwarded': new_message.is_forwarded,
                    'forwarded_from': new_message.forwarded_from.username if new_message.forwarded_from else None,
                }
            )

        if not forwarded_messages:
            return Response({"error": "Message could not be forwarded to any of the provided chats."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Message forwarded successfully."}, status=status.HTTP_200_OK)


class VoteOnPollView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, poll_id, option_id):
        poll_option = get_object_or_404(PollOption, id=option_id, poll_id=poll_id)
        poll = poll_option.poll
        message = get_object_or_404(Message, poll=poll)

        if request.user not in message.chat.participants.all():
            return Response({"error": "You are not a participant in this chat."}, status=status.HTTP_403_FORBIDDEN)

        # Check if the user has already voted on this poll
        if PollVote.objects.filter(poll_option__poll=poll, user=request.user).exists():
            return Response({"error": "You have already voted on this poll."}, status=status.HTTP_400_BAD_REQUEST)

        vote = PollVote.objects.create(poll_option=poll_option, user=request.user)

        # WebSocket event for real-time update
        channel_layer = get_channel_layer()
        serializer = PollSerializer(poll)
        async_to_sync(channel_layer.group_send)(
            f"chat_{message.chat.id}",
            {
                "type": "poll_vote_update",
                "poll": serializer.data,
            },
        )

        return Response({"message": "Vote cast successfully."}, status=status.HTTP_201_CREATED)
