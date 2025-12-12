# Allumette - Decentralized Matchmaking Signaling Server

Allumette is a signaling server designed for `ggrs` (rollback netcode library) games, leveraging `matchbox-socket` for robust peer-to-peer connections. It provides a decentralized and stateless matchmaking service with a focus on flexibility and extensibility.

## Key Features

1.  **Decentralized Matchmaking:** Facilitates direct peer-to-peer connections for games, reducing reliance on central authorities for gameplay.
2.  **Stateless Authentication:** Implements a secure, stateless authentication system using JWTs, ensuring scalable and flexible user management.
3.  **Lobby Management:**
    *   **Public Lobbies:** Easily discoverable and joinable lobbies for open matchmaking.
    *   **Private Lobbies:** Invite-only lobbies with optional whitelisting, perfect for friends or competitive play.
4.  **Offline Account with Friends:** Supports managing friend relationships and accounts that persist across sessions.
5.  **WebSocket Integration:** Utilizes WebSockets for real-time communication between clients and the signaling server, enabling dynamic lobby updates and game state synchronization.
6.  **Web Interface for UI Development:** Includes `allumette_web` (a SvelteKit application) to aid in building intuitive web-based user interfaces for matchmaking and lobby management.
7.  **Comprehensive Integration Test Suite:** A robust suite of integration tests ensures the stability and correctness of the API and core functionalities.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

*   Rust toolchain (with `cargo`)
*   `just` (command runner, alternative to `make`)
*   `npm` (for the `allumette_web` frontend)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/bascanada/matchbox-server.git
    cd matchbox-server
    ```

2.  **Build the server:**
    ```bash
    cargo build
    ```

3.  **Install frontend dependencies:**
    ```bash
    cd allumette_web
    npm install
    cd ..
    ```

## Running the Server

To run the Allumette server locally:

```bash
make run
```

The server will typically run on `127.0.0.1:3536`.

## Running the Web Interface

To run the SvelteKit web interface:

```bash
cd allumette_web
npm run dev
```

This will start the development server for the web UI, usually accessible at `http://localhost:5173`.

## Running Tests

To execute the comprehensive test suite, including unit and integration tests:

```bash
make test
```

## Project Structure

*   `src/`: Core Rust server-side logic, including authentication, lobby management, and state handling.
*   `allumette_web/`: SvelteKit frontend application for the web interface.
*   `tests/`: Integration tests for the server API.
*   `examples/`: Example client usage.

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.