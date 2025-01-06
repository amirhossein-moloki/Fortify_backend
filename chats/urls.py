from django.urls import path
from .views import CreateChatView, UpdateChatView, DeleteChatView, AddUserToChatView, RemoveUserFromChatView, GetUserChatsView, SearchChatsView, get_chat_participants, LeaveChatView

urlpatterns = [
    path('chat/create/', CreateChatView.as_view(), name='create_chat'),
    path('chat/<int:chat_id>/update/', UpdateChatView.as_view(), name='update_chat'),
    path('chat/<int:chat_id>/delete/', DeleteChatView.as_view(), name='delete_chat'),
    path('chat/<int:chat_id>/add-users/', AddUserToChatView.as_view(), name='add_users_to_chat'),
    path('chat/<int:chat_id>/remove-users/', RemoveUserFromChatView.as_view(), name='remove_users_from_chat'),
    path('chat/<int:chat_id>/leave/', LeaveChatView.as_view(), name='leave_chat'),
    path('', GetUserChatsView.as_view(), name='get_user_chats'),
    path('chats/search/', SearchChatsView.as_view(), name='search_chats'),
    path('chat/<int:chat_id>/participants/', get_chat_participants, name='get_chat_participants'),
]
