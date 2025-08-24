# Voice Call Signaling Protocol

This document outlines the WebSocket signaling protocol for establishing and managing voice calls.

## 1. Connection

The client must connect to the following WebSocket endpoint:

```
ws://<your_server_address>/ws/call/?token=<jwt_access_token>
```

The JWT access token must be provided as a query parameter for authentication.

## 2. Signaling Flow

Here is the sequence of events for a typical call:

### Step 1: Initiating a Call (Caller)

To start a call with another user, the caller sends a `start_call` event.

**Client -> Server:**
```json
{
  "action": "start_call",
  "callee_id": <user_id_of_callee>
}
```

### Step 2: Receiving an Incoming Call (Callee)

The callee's client will receive an `incoming_call` event. The frontend should use this to display an incoming call notification.

**Server -> Callee's Client:**
```json
{
  "type": "incoming_call",
  "call_id": <unique_id_for_the_call>,
  "caller_id": <user_id_of_caller>,
  "caller_username": "caller_username"
}
```

### Step 3: Answering the Call (Callee)

If the callee accepts the call, they must send an `answer_call` event.

**Callee's Client -> Server:**
```json
{
    "action": "answer_call",
    "call_id": <call_id_from_incoming_call>,
    "caller_id": <user_id_of_caller>
}
```

The server will then notify the caller that the call was answered.

**Server -> Caller's Client:**
```json
{
    "type": "call_answered",
    "callee_id": <user_id_of_callee>
}
```
At this point, the WebRTC peer connection can begin.

### Step 4: WebRTC Offer/Answer Exchange

The peers now exchange SDP offers and answers.

**Caller's Client -> Server:**
```json
{
  "action": "offer",
  "callee_id": <user_id_of_callee>,
  "offer": { ... } // SDP offer object
}
```

**Server -> Callee's Client:**
```json
{
  "type": "call_offer",
  "offer": { ... }, // SDP offer object
  "caller_id": <user_id_of_caller>
}
```

**Callee's Client -> Server:**
```json
{
  "action": "answer",
  "caller_id": <user_id_of_caller>,
  "answer": { ... } // SDP answer object
}
```

**Server -> Caller's Client:**
```json
{
  "type": "call_answer",
  "answer": { ... }, // SDP answer object
  "callee_id": <user_id_of_callee>
}
```

### Step 5: ICE Candidate Exchange

The peers exchange ICE candidates to find the best path for the connection. This happens concurrently with the offer/answer exchange.

**Client (either) -> Server:**
```json
{
  "action": "ice_candidate",
  "peer_id": <user_id_of_the_other_peer>,
  "candidate": { ... } // ICE candidate object
}
```

**Server -> Other Client:**
```json
{
  "type": "ice_candidate",
  "candidate": { ... }, // ICE candidate object
  "sender_id": <user_id_of_sender>
}
```

### Step 6: Ending the Call

Either user can hang up the call.

**Client (either) -> Server:**
```json
{
  "action": "hang_up",
  "peer_id": <user_id_of_the_other_peer>,
  "call_id": <the_current_call_id>
}
```

**Server -> Other Client:**
```json
{
  "type": "call_hanged_up",
  "hanged_up_by": <user_id_of_who_hung_up>
}
```

## 3. Other Call Events

### Rejecting a Call (Callee)

If the callee rejects the incoming call.

**Callee's Client -> Server:**
```json
{
    "action": "reject_call",
    "call_id": <call_id_from_incoming_call>,
    "caller_id": <user_id_of_caller>
}
```
**Server -> Caller's Client:**
```json
{
    "type": "call_rejected",
    "callee_id": <user_id_of_callee>
}
```

### Cancelling a Call (Caller)

If the caller cancels the call before it is answered.

**Caller's Client -> Server:**
```json
{
    "action": "cancel_call",
    "call_id": <the_current_call_id>,
    "callee_id": <user_id_of_callee>
}
```

**Server -> Callee's Client:**
```json
{
    "type": "call_cancelled",
    "caller_id": <user_id_of_caller>
}
```
