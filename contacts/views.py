from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from .models import Contact, Block
from .serializers import ContactSerializer

User = get_user_model()

class BlockUserView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, username):
        try:
            blocked_user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user == blocked_user:
            return Response({"error": "You cannot block yourself."}, status=status.HTTP_400_BAD_REQUEST)

        _, created = Block.objects.get_or_create(blocker=request.user, blocked=blocked_user)

        if created:
            return Response({"message": f"User {username} has been blocked."}, status=status.HTTP_201_CREATED)
        return Response({"message": f"User {username} was already blocked."}, status=status.HTTP_200_OK)

    def delete(self, request, username):
        try:
            blocked_user = User.objects.get(username=username)
            block = Block.objects.get(blocker=request.user, blocked=blocked_user)
            block.delete()
            return Response({"message": f"User {username} has been unblocked."}, status=status.HTTP_204_NO_CONTENT)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        except Block.DoesNotExist:
            return Response({"error": "You have not blocked this user."}, status=status.HTTP_404_NOT_FOUND)


class ContactListView(generics.ListAPIView):
    serializer_class = ContactSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Contact.objects.filter(user=self.request.user)

class FriendRequestActionView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, pk, action):
        try:
            contact = Contact.objects.get(pk=pk, contact=request.user)
        except Contact.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        if action == 'accept':
            contact.status = 'accepted'
            # Create a reverse contact for the user who sent the request
            Contact.objects.create(user=contact.contact, contact=contact.user, status='accepted')
        elif action == 'reject':
            contact.status = 'rejected'
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        contact.save()
        serializer = ContactSerializer(contact)
        return Response(serializer.data)

class ContactCreateView(generics.CreateAPIView):
    serializer_class = ContactSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class ContactDeleteView(generics.DestroyAPIView):
    serializer_class = ContactSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Contact.objects.filter(user=self.request.user)
