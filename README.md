# Secure Onlie Data Transfer - Mobile
An sodt android client for data transfer on mobile devices.

## How to Use

To use the app, first open the preferences and set your server settings, such as the server address, port and RSA public key.
After saving your preferences, connect to the server. 
Once connected, you will see a list of available clients. Select a client from the list to initiate a connection. To send a file click on the send file button and choose the desired file. 
Receiving files is handled automatically and passively by the app - no user action is required to accept incoming files.

## Packet Structure

A message sent to/from the server has the following format:

[targetIdByte, sourceIdByte, sizeByte1, sizeByte2, dataByte0, dataByte1, ..., dataByteN]


- targetIdByte: Defines the receiver.
- sourceIdByte: Defines the sender.
- sizeByte1 and sizeByte2: Represent an encoded ushort (2^16 bytes) that indicates how many dataBytes are being sent.
- each message send has a total size of 4096 bytes = 2 id bytes + 2 size bytes + 4092 data bytes (with potential padding)
- each message is encrypted (see below)
- dataByte0, ..., dataByteN: Contain the encoded JSON messages defined below.
- Id = 0 is reserved for clients with no assigned Id.
- Id = 1 is reserved for the server. Packets with targetId = 1 will be read and handled by the server.
- Any other positive number >1 will result in the packet being redirected to the client with that ID, if the ID can be resolved.


## Encryption and Compression
Each message is encrypted as followed:
#### default encryped message
- targetIdByte and sourceIdByte are unencrypted (to ensure fast server-side redirection)
- sizeBytes and dataBytes are encrypted with matching AES. encryptedByteArray = enc_aes([sizeByte1, sizeByte2, dataByte1, ... dataByteN])
#### special case initial discorvery message (only client -> server)
- targetIdByte and sourceIdByte are unencrypted
- sizeBytes and dataBytes are encrypted with the server public RSA key. encryptedByteArray = enc_rsa([sizeByte1, sizeByte2, dataByte1, ... dataByteN])

### Client -> Server (Discovery)
When sending the initial discovery request, the client sends their **new generated AES session key** to the server and encrypts the discovery message using the **bundled key** from the server.
### Server <-> Client
#### AES (Cipher mode: CFB)
AES is used to encrypt and decrypt the protocol requests from the server to a client.

---

### Client <-> Client
#### ECDH
Elliptic Curve Diffie-Hellman (with nistP256 curve) is used to securely generate the AES Session Key. Therefore the server cannot know the current session key.
#### AES (Cipher mode: CFB)
This symmetric Encryption will be used for the actual data transfer.

#### Compression
Not supported yet: Gzip is used to compress a file before being sent.


# Protocol (JSON)
## Server Protocol
### Codes
- 100: Request
- 200: Succeed (response)
- 300: Denied (response)
- 400: Error (response)

### Discovery
(Sender) Initial discovery  
```json
{"type": "discovery", "code": 100, "uuid": 1337, "key": "key", "iv": "iv", "id": 0}
//key and iv are byte arrays encoded with the server RSA public key
// id is always 0 at initial discorvery
```
(Receiver) Response -> Added to online list 
```json
{"type": "discovery", "code": 200, "uuid": 456, "key": null, "iv": null, "id": 42} 
```
### Key Exchnage
(Sender Client) Key Exchange Request
```json
{"type": "exchange", "code": 100, "uuid": 1111, "key": "Sender ECDH Public Key", "sessionHash": "hash", "targetId": 42, "sourceId": 24}
// key and iv are byte arrays encoded as string
```
(Receiver Client) Key Exchange Respone 
```json
{"type": "exchange", "code": 200, "uuid": 879, "key": "Receiver ECDH PublicKey", "sessionHash": "hash", "targetId": 24, "sourceId": 42}
// key and sessionHash are byte arrays encoded as string
// sessionHash (session password set by user) may be null 
```
(Sent by Server) Key Exchange Error
```json
{"type": "exchange", "code": 400, "uuid": 1111, "key": "Receiver ECDH PublicKey", "sessionHash": "hash", "targetId": 24, "sourceId": 42}
// the error packet is identical to "(Sender Client) Key Exchange Request" except new uuid and targetId and sourceId are switched
```

### Client List
(Sender) Request a list of all the connected clients
```json
{"type": "clients", "code": 100, "uuid": 454, "clients": null} 
```
(Sent by Server to ALL clients) Response -> Update available clients
```json
{"type": "clients", "uuid": 181, "code": 200, "clients": ""}
// clients is a byte array encoded as string
```

### Disconnect
(Sender) Requests to disconnect to server
```json
{"type": "disconnect", "code": 100, "uuid": 1337} 
```
(Server) Disconnects Client(Removes it from internal caches). 

No Response sent. but Server sends an updated client list to all clients

```json
{"type": "clients", "uuid": 181, "code": 200, "clients": ""}
// clients is a byte array encoded as string
```


---


## Client Protocol

### Transfer Request
(Sender) Request
```json
{"type": "transfer", "uuid": 69420, "filename": "homework.zip", "size": 10000000, "sourceId": 42, "code": 100}
```
(Receiver) Response
```json
{"type": "transfer", "uuid": 69420, "filename": "homework.zip", "size": 10000000, "sourceId": 24 "code": 200}
// note that the response uuid is identical to the request uuid
```
#### Actual Transfer
(Sender) Package 1
```json
{"type": "file", "uuid": 69420, "code": 100, "position": 0, "data":""}
```
(Sender) Package 2
```json
{"type": "file", "uuid": 69420, "code": 100, "position": 3003, "data":""}
// note that the uuid is identical to the respective transfer request
// data is an byte array encoded as string
// position marks start point for data in the file
```
...

(Sender) Package N



(Receiver) Does not acknowlage received packages. No response is sent.
