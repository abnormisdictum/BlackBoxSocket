# BlackBoxSocket
My twist to a Java based secure layer for socket communication.
Essentially what it does is as follows:
1. When a BlackBox Client or Server is connects client send over the client's public key.
2. Then the server send it's public key to client
3. Then, depending on whether the BlackBoxSocket is client controlled or server controlled, the client or server respectively generates two AES Keys.
  a. A Aes SecretKey that encrypts the Message JSON string, known as OuterLayerSecretKey
  b. A Aes SecretKey which is used as the key for a Time-based OTP algotrithm to generate further Aes keys for each message.
4. Once that is done, each message interaction can be done using the Message class.
5. The message class:
  a. Accepts the String message.
  b. Creates and stores a signature of the message using Rsa and the Client/Server 's privateKey.
  c. Generates a Salt that is used to create the Message's AES SecretKey.
  d. Generates the AES Key using MessageSecretKey and Salt and then encrypts and stores the message in the Message class.
  e. The Message Class toString() function returns a JSON String containing all the message data parameters except time.
6. When the remote device recieves the Encrypted String
  a. It decrypts it to get the JSON String using OuterLayerSecretKey.
  b. Then creates a Message object by passing the JSON String along with the MessageSecretKey and the remote devices public key, and then stores the OTP timestamp.
  c. It outputs the message in the object using the getMessage() function which
    i. Generates the messages SecretKey using MessageSecretKey and the timestamp.
    ii. Authenticates the message using remote devices public key, if it failes to authenticate, it destroys the data.
    iii. Decrypts the message using the newly generated message Key and outputs the message.
    
The program thus relies on the devices to generate each individual message key. Thereby improving security, at least in my head.

DISCLAIMER: I am a novice java programmer and I have no professional background in java programming or programming in general. I am an Electronics Engineer.
As you will no doubt figure out when you read my source code, I have done a very very poor job of Exception handeling. If anyone can smooth over this program, i'd like that a lot.
This program algorithm is mine. I came up with it on my own. So anyone can use it and do whatever they want with it as long as they tell me the changes they made and why.
I'd like to learn, thats all. No other reason. Now laugh at my novice-ness. :D
