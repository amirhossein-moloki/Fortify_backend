import json
import pytest
from channels.db import database_sync_to_async
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Call
from Fortify_back.asgi import application

User = get_user_model()

@pytest.mark.django_db
class CallModelTest(TestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='password')
        self.user2 = User.objects.create_user(username='user2', password='password')

    def test_call_creation(self):
        call = Call.objects.create(caller=self.user1, callee=self.user2)
        self.assertEqual(call.caller, self.user1)
        self.assertEqual(call.callee, self.user2)
        self.assertEqual(call.status, 'initiating')

    def test_call_status_transitions(self):
        call = Call.objects.create(caller=self.user1, callee=self.user2, status='ringing')

        call.answer_call()
        self.assertEqual(call.status, 'active')

        call.end_call()
        self.assertEqual(call.status, 'ended')
        self.assertIsNotNone(call.duration)

        call = Call.objects.create(caller=self.user1, callee=self.user2, status='ringing')
        call.reject_call()
        self.assertEqual(call.status, 'rejected')

        call = Call.objects.create(caller=self.user1, callee=self.user2, status='ringing')
        call.miss_call()
        self.assertEqual(call.status, 'missed')

        call = Call.objects.create(caller=self.user1, callee=self.user2, status='initiating')
        call.cancel_call()
        self.assertEqual(call.status, 'cancelled')


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
class CallConsumerTest(TestCase):
    async def asyncSetUp(self):
        self.user1 = await User.objects.acreate(username='user1', password='password')
        self.user2 = await User.objects.acreate(username='user2', password='password')

        refresh1 = await database_sync_to_async(RefreshToken.for_user)(self.user1)
        self.token1 = str(refresh1.access_token)

        refresh2 = await database_sync_to_async(RefreshToken.for_user)(self.user2)
        self.token2 = str(refresh2.access_token)

    async def test_call_signaling_flow(self):
        await self.asyncSetUp()

        communicator1 = WebsocketCommunicator(application, f"/ws/call/?token={self.token1}")

        communicator2 = WebsocketCommunicator(application, f"/ws/call/?token={self.token2}")

        connected1, _ = await communicator1.connect()
        self.assertTrue(connected1)

        connected2, _ = await communicator2.connect()
        self.assertTrue(connected2)

        # 1. User1 starts a call to User2
        await communicator1.send_to(text_data=json.dumps({
            'action': 'start_call',
            'callee_id': self.user2.id
        }))

        # 2. User2 receives the incoming call notification
        response = await communicator2.receive_from()
        data = json.loads(response)
        self.assertEqual(data['type'], 'incoming_call')
        self.assertEqual(data['caller_id'], self.user1.id)
        call_id = data['call_id']

        # 3. User2 answers the call
        await communicator2.send_to(text_data=json.dumps({
            'action': 'answer_call',
            'call_id': call_id,
            'caller_id': self.user1.id,
        }))

        # 4. User1 receives 'call_answered'
        response = await communicator1.receive_from()
        data = json.loads(response)
        self.assertEqual(data['type'], 'call_answered')
        self.assertEqual(data['callee_id'], self.user2.id)

        # 5. Exchange offer/answer/ice
        offer = {'sdp': '...'}
        await communicator1.send_to(text_data=json.dumps({
            'action': 'offer',
            'callee_id': self.user2.id,
            'offer': offer
        }))
        response = await communicator2.receive_from()
        data = json.loads(response)
        self.assertEqual(data['type'], 'call_offer')
        self.assertEqual(data['offer'], offer)

        answer = {'sdp': '...'}
        await communicator2.send_to(text_data=json.dumps({
            'action': 'answer',
            'caller_id': self.user1.id,
            'answer': answer
        }))
        response = await communicator1.receive_from()
        data = json.loads(response)
        self.assertEqual(data['type'], 'call_answer')
        self.assertEqual(data['answer'], answer)

        candidate = {'candidate': '...'}
        await communicator1.send_to(text_data=json.dumps({
            'action': 'ice_candidate',
            'peer_id': self.user2.id,
            'candidate': candidate
        }))
        response = await communicator2.receive_from()
        data = json.loads(response)
        self.assertEqual(data['type'], 'ice_candidate')
        self.assertEqual(data['candidate'], candidate)

        # 6. Hang up
        await communicator1.send_to(text_data=json.dumps({
            'action': 'hang_up',
            'peer_id': self.user2.id,
            'call_id': call_id
        }))
        response = await communicator2.receive_from()
        data = json.loads(response)
        self.assertEqual(data['type'], 'call_hanged_up')

        # 7. Check call status in DB
        call = await Call.objects.aget(id=call_id)
        self.assertEqual(call.status, 'ended')

        await communicator1.disconnect()
        await communicator2.disconnect()
