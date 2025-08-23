from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/key_exchange/', consumers.KeyExchangeConsumer.as_asgi()),
]
