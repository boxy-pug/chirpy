# Chirpy Web Server

This project is a web server application developed as part of an assignment for Boot.dev. The Chirpy web server provides a platform for users to create, manage, and interact with chirps (short messages), along with user authentication and management features.

## Features

-  User registration and authentication
-  JWT-based session management
-  Chirp creation, retrieval, update, and deletion
-  Metrics and health check endpoints for server monitoring
-  Webhook integration for external services

## API Endpoints

Below is a list of available API endpoints and their functionalities:

### Health and Metrics

-  **GET `/api/healthz`**: Check the health status of the server.
-  **GET `/admin/metrics`**: Retrieve server metrics.

### User Management

-  **POST `/api/users`**: Register a new user.
-  **POST `/api/login`**: Authenticate a user and obtain access and refresh tokens.
-  **POST `/api/refresh`**: Refresh the access token using a refresh token.
-  **POST `/api/revoke`**: Revoke a refresh token.
-  **PUT `/api/users`**: Update a user's email and password.

### Chirp Management

-  **POST `/api/chirps`**: Create a new chirp.
-  **GET `/api/chirps`**: Retrieve all chirps.
-  **GET `/api/chirps/{chirpID}`**: Retrieve a specific chirp by ID.
-  **DELETE `/api/chirps/{chirpID}`**: Delete a specific chirp by ID.

### Admin

-  **POST `/admin/reset`**: Reset server data (restricted to development environment).

### Webhooks

-  **POST `/api/polka/webhooks`**: Handle incoming webhooks to update chirps to Chirpy Red.

## Middleware

-  **Middleware for Metrics**: `mux.Handle("/app/", apiCfg.middlewareMetricsInc(handler))` is used to track and increment server metrics for each request.

## Getting Started

### Prerequisites

-  Go 1.16 or later
-  PostgreSQL database

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/chirpy.git
   cd chirpy
   ```

2. Set up environment variables in a `.env` file:
   ```
   DB_URL=your_database_url
   JWT_SECRET=your_jwt_secret
   PLATFORM=dev
   ```

3. Run the server:
   ```bash
   go run cmd/server/main.go
   ```

## License

This project is licensed under the MIT License.

## Acknowledgments

This project is developed as part of the Boot.dev curriculum. Special thanks to the Boot.dev team for their guidance and support.