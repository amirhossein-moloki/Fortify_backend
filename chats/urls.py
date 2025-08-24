from django.urls import path
from .views import (
    CreateChatView, UpdateChatView, DeleteChatView, AddUserToChatView,
    RemoveUserFromChatView, GetUserChatsView, SearchChatsView,
    get_chat_participants, LeaveChatView, download_attachment, ReactToMessageView,
    PinMessageView, ForwardMessageView, VoteOnPollView, SearchMessagesView
)

urlpatterns = [
    path('attachment/<int:attachment_id>/', download_attachment, name='download_attachment'),
    path('polls/<int:poll_id>/options/<int:option_id>/vote/', VoteOnPollView.as_view(), name='poll_vote'),
    path('messages/<int:message_id>/react/', ReactToMessageView.as_view(), name='react_to_message'),
    path('messages/<int:message_id>/forward/', ForwardMessageView.as_view(), name='forward_message'),
    path('chat/create/', CreateChatView.as_view(), name='create_chat'),
    path('chat/<int:chat_id>/update/', UpdateChatView.as_view(), name='update_chat'),
    path('chat/<int:chat_id>/delete/', DeleteChatView.as_view(), name='delete_chat'),
    path('chat/<int:chat_id>/add-users/', AddUserToChatView.as_view(), name='add_users_to_chat'),
    path('chat/<int:chat_id>/remove-users/', RemoveUserFromChatView.as_view(), name='remove_users_from_chat'),
    path('chat/<int:chat_id>/leave/', LeaveChatView.as_view(), name='leave_chat'),
    path('chat/<int:chat_id>/pin/<int:message_id>/', PinMessageView.as_view(), name='pin_message'),
    path('chat/<int:chat_id>/search/', SearchMessagesView.as_view(), name='search_messages'),
    path('', GetUserChatsView.as_view(), name='get_user_chats'),
    path('chats/search/', SearchChatsView.as_view(), name='search_chats'),
    path('chat/<int:chat_id>/participants/', get_chat_participants, name='get_chat_participants'),
]
