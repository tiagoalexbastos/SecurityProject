# SecurityProject
Security Project - 2016

Secure Instant Messaging System

Instant messaging applications are a vital component in todays communica- tions, through which users exchange trivia, business related and even private information. Therefore, the impact of a security breach is very high as it may allow an attacker to pursue with attacks directed to obtain monetary compensation (e.g, using credit card numbers), or damaging systems (e.g, using stolen credentials).
The objective of this project is to develop a system enabling users to ex- change short instant messages. The resulting system is composed by a Ren- dezvous Point, or Server, and several clients exchanging messages. The system should be designed to support the following security features:
• - Message confidentiality, integrity and authentication: Messages cannot be eavesdropped, modified or injected by a third party or the server;
• - Destination validation: Sender can determine that messages are really delivered to the correct destination;
• - Identity preservation: There is a direct association between one user and one Portuguese Citizen, and vice-versa, using the Portu- guese Citizen Card;
• - Information Flow Control: There is a specific control over the information flow using the Bell-LaPadula information flow policy;
• - Multiple Cipher Support: Components can negotiate the appropriate ciphers to use;
• - Forward secrecy: Compromise of a specific session key doesn’t allow access to traffic sent in future sessions;
• - Backward secrecy: Compromise of a specific session key do- esn’t allow access to traffic sent in past sessions;
• - Participant consistency: A receiver can detect if a message from a sender originates from a different device;
• - Conversation consistency: Message order of a conversation stored locally forms a unidirectional chain that can be validated offline by each client;
