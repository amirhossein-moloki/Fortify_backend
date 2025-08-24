# Fortify-backend: A Secure Chat Application Backend

This repository contains the backend for **Fortify**, a modern and secure chat application built with **Django** and **Django Rest Framework**. The core mission of this project is to ensure user privacy through robust **End-to-End Encryption (E2EE)** for all conversations and file transfers.

<br>

## 🌟 Key Features

Fortify implements a comprehensive suite of features expected from a professional-grade messaging application:

### 🔐 Security & User Management
- **Professional Authentication System**: Secure user registration with email activation, Two-Factor Authentication (2FA) via email OTP, and complete session management.
- **End-to-End Encryption (E2EE)**: All messages and files are encrypted using modern cryptographic algorithms. The encryption keys are held only by the client-side users, ensuring the server has no access to the plaintext data.
- **Advanced Profile Management**: Users can customize their profiles with a display picture, banner image, bio, and more.
- **High-Level Security**: Implements JWT with refresh and blacklist capabilities, along with rate limiting on sensitive endpoints to prevent brute-force attacks.
- **User Blocking**: Allows users to block others, preventing any further communication.

### 💬 Advanced Chat System
- **Real-time Messaging**: Built with Django Channels for low-latency, persistent WebSocket connections.
- **Full Message Control**: Supports **editing**, **deleting**, **replying to**, and **forwarding** messages.
- **Chat Diversity**: Supports one-on-one (direct), group, and channel-based conversations.
- **Secure File Sharing**: Encrypted transfer of images, videos, and other file attachments.
- **Interactive Features**:
  - **Message Reactions**
  - **In-chat Polls**
  - **Typing Indicators**
  - **Message Status**: Sent, Delivered, and Read receipts.
  - **Pinned Messages** within chats.

### 📞 Voice & Video Calls
- **Real-time Calls with WebRTC**: A complete signaling backend to establish peer-to-peer (P2P) voice and video calls.
- **Call Lifecycle Management**: Handles the entire call flow, including initiation, answering, rejection, and hang-up.

### 👥 Contact Management
- **Friend Request System**: Users can add new contacts by sending and accepting friend requests.
- **Contact List**: View and manage the list of contacts.

<br>

## 🛠️ Installation & Setup

Follow these steps to run the project locally:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/fortify-backend.git
    cd fortify-backend
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    # On Windows
    # venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure environment variables:**
    Create a `.env` file in the project root. Copy the contents of `.env.example` and fill in your details.
    ```env
    DJANGO_SECRET_KEY=your-secret-key
    DEBUG=True
    ALLOWED_HOSTS=localhost,127.0.0.1

    # Database (example for SQLite)
    DATABASE_URL=sqlite:///db.sqlite3

    # Redis for Channels
    REDIS_URL=redis://localhost:6379/1

    # Email Configuration
    EMAIL_HOST=your-email-host
    EMAIL_PORT=your-email-port
    EMAIL_USE_SSL=True
    EMAIL_HOST_USER=your-email-host-user
    EMAIL_HOST_PASSWORD=your-email-host-password
    ```

5.  **Run database migrations:**
    ```bash
    python manage.py migrate
    ```

6.  **Run the development server:**
    ```bash
    python manage.py runserver
    ```
    The backend is now available at `http://127.0.0.1:8000`.

<br>

## 🧪 Running Tests

To ensure the integrity of the application, run the test suite:
```bash
python manage.py test
```

<br>

## 🚀 Running with Docker

For a more streamlined setup, you can use Docker and Docker Compose to run the entire application stack, including the database and Redis.

1.  **Prerequisites:**
    *   [Docker](https://www.docker.com/get-started) installed on your machine.
    *   [Docker Compose](https://docs.docker.com/compose/install/) (usually included with Docker Desktop).

2.  **Environment File:**
    The `docker-compose.yml` file is pre-configured with development environment variables. You can modify the `environment` section under the `web` service in `docker-compose.yml` or create a `.env` file for production overrides.

3.  **Build and Run:**
    From the project root directory, run the following command:
    ```bash
    docker-compose up --build
    ```
    This command will:
    *   Build the Docker image for the Django application.
    *   Start the `web`, `db` (PostgreSQL), and `redis` services.
    *   Apply database migrations automatically.

    The application will be available at `http://localhost:8000`.

4.  **Stopping the Application:**
    To stop the services, press `Ctrl+C` in the terminal where `docker-compose` is running, and then run:
    ```bash
    docker-compose down
    ```
