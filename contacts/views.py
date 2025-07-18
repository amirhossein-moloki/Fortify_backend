from rest_framework import generics, permissions
from .models import Contact
from .serializers import ContactSerializer

class ContactListView(generics.ListAPIView):
    serializer_class = ContactSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Contact.objects.filter(user=self.request.user)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

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
