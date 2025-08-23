from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from urllib.parse import parse_qs
from channels.exceptions import DenyConnection
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.exceptions import AuthenticationFailed

User = get_user_model()

class TokenAuthMiddleware:
    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        query_params = parse_qs(scope.get('query_string', b'').decode())
        token = query_params.get('token', [None])[0]

        if not token:
            headers = dict(scope['headers'])
            if b'authorization' in headers:
                token = headers[b'authorization'].decode().split(' ')[1]

        if not token:
            raise DenyConnection("No token provided.")

        try:
            user = await self.get_user_from_token(token)
            if user is None:
                raise AuthenticationFailed("Invalid token")
            scope['user'] = user
        except AuthenticationFailed as e:
            raise DenyConnection(str(e))

        return await self.inner(scope, receive, send)

    @database_sync_to_async
    def get_user_from_token(self, token):
        try:
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            return User.objects.get(id=user_id)
        except (Exception, AuthenticationFailed):
            return None
