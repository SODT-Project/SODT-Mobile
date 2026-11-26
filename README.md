# SODT Mobile
SODT Mobile is an Android mobile client for sending and receiving files over a SODT server via the SODT protocol.

## How It Works

1. The client connects to a given SODT server.
2. The server provides the IDs of other connected clients.
3. The clients perform a key exchange before communicating securely.
4. A file transfer is requested and starts once the receiving client accepts it.

The client uses ECDH to establish a session key. Messages and file data are then encrypted with AES-GCM.

## Features

- ECDH key exchange for secure client sessions
- AES-GCM encryption for messages and file transfers
- Each session with a new client is assigned its own shared phrase. Verify this phrase with the other client to confirm authenticity.
- Send files to other connected clients
- Receive files in the Downloads folder
- View live progress while receiving files
- Optional automatic acceptance of key exchanges and file transfers
- Continue sending and receiving even when the app is minimized
- View the most recent logs in the Logs tab

## Usage
### Installation
- Install from the F-Droid Store (coming soon!)

### Running the App
<img width="540" height="1200" alt="Default App after Startup" src="https://github.com/user-attachments/assets/7aa5a530-9870-4fb5-af60-69d420a01848" />

1. Open the app.
2. Allow notifications if prompted.

<img width="270" height="700" alt="App Preferences" src="https://github.com/user-attachments/assets/439302bb-8752-4d40-9da2-66c8202a6a35" />

3. Set the Server, Port, and Key in Preferences.

<img width="270" height="700" alt="Connect to Server" src="https://github.com/user-attachments/assets/597a7e14-0b5f-496a-b3de-936432aa651a" />

4. Connect to the server.

<img width="270" height="700" alt="Connected To Server" src="https://github.com/user-attachments/assets/5870be7d-470c-401e-abcd-aea8090a9f98" />

5. Tap on other clients to select them and exchange keys.

<img width="270" height="700" alt="Allow File Transfer" src="https://github.com/user-attachments/assets/eb209bb1-b5f7-422c-a041-ba1536c191ea" />
<img width="270" height="700" alt="Screenshot_20261126_183647" src="https://github.com/user-attachments/assets/96a42c45-2a45-4bf6-8ece-3e1344cda560" />

6. Allow incoming file transfers.
