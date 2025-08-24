import django
django.setup()

import os
import django
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import re_path
from chats import consumers as chat_consumers
from accounts.middlewares import TokenAuthMiddleware
from accounts import consumers as status_consumers
from notifications import consumers as notification_consumers
from encryption import routing as encryption_routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Fortify_back.settings')
django.setup()

# تعریف برنامه ASGI
application = ProtocolTypeRouter({
    # مدیریت درخواست‌های HTTP
    "http": get_asgi_application(),

    # مدیریت ارتباطات WebSocket
    "websocket": TokenAuthMiddleware(
        URLRouter([
            # مسیر WebSocket برای چت
            re_path(r'^ws/chat/(?P<chat_id>\d+)/$', chat_consumers.ChatConsumer.as_asgi(), name="chat_websocket"),

            # مسیر WebSocket برای وضعیت حضور کاربران
            re_path(r'ws/presence/$', status_consumers.PresenceConsumer.as_asgi()),

            # مسیر WebSocket برای نوتیفیکیشن‌ها
            re_path(r'ws/notifications/$', notification_consumers.NotificationConsumer.as_asgi()),
        ] + encryption_routing.websocket_urlpatterns)
    ),
})
