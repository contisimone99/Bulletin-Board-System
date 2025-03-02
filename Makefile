all: client server clean

client: DH.o crypto_utility.o clientImpl.o cipher.o  utility.o client.o 
	g++ -Wall -std=c++17 -o client crypto_utility.o utility.o clientImpl.o  client.o -lssl -lcrypto

server: DH.o  crypto_utility.o serverImpl.o cipher.o  utility.o server.o 
	g++ -Wall -std=c++17 -o server DH.o crypto_utility.o utility.o  serverImpl.o  server.o  -lssl -lcrypto 

client.o: Client/client.cpp
	g++ -c  -Wall -std=c++17 Client/client.cpp -o client.o 

clientImpl.o: Client/clientImpl.cpp
	g++ -c  -Wall -std=c++17 Client/clientImpl.cpp -o clientImpl.o

serverImpl.o: Server/serverImpl.cpp
	g++ -c  -Wall -std=c++17 Server/serverImpl.cpp -o serverImpl.o

server.o: Server/server.cpp
	g++ -c  -Wall -std=c++17 Server/server.cpp -o server.o

cipher.o: lib/cipher.cpp
	g++ -c  -Wall -std=c++17 lib/cipher.cpp -o cipher.o

DH.o: lib/DH.cpp
	g++ -c  -Wall -std=c++17 lib/DH.cpp -o DH.o

crypto_utility.o: lib/crypto_utility.cpp
	g++ -c  -Wall -std=c++17 lib/crypto_utility.cpp -o crypto_utility.o

utility.o: lib/utility.cpp
	g++ -c  -Wall -std=c++17 lib/utility.cpp -o utility.o

clean:
	rm -f client.o server.o DH.o cipher.o crypto_utility.o utility.o serverImpl.o clientImpl.o session.o
