#include "server.h"

Server::Server(uint16_t serverPort)
{
   port = serverPort;
   listener = 0;
   new_socket = 0;
   sd = 0;
   memset(&address, 0, sizeof(address));
   address.sin_family = AF_INET;
   address.sin_addr.s_addr = INADDR_ANY;
   address.sin_port = htons(port);
   // TODO: pubkey gen
   id_clients = 0;
}

void Server::run()
{
   /*
   EVP_PKEY *privKey = generate_privK();
   write_pem_file("privKey.pem", privKey);
   //std::cout << "Private key generated and saved in server_privKey.pem" << std::endl;
   get_pubK_from_privK(privKey, "server_pubKey.pem");
   //write_pem_file("server_pubKey.pem", pubKey, "PUBLIC"); non serve più, la chiave pubblica è già stata salvata con get_pubK_from_privK
   std::cout << "Public key generated and saved in server_pubKey.pem" << std::endl;
   EVP_PKEY *pubkey = read_pem_file("server_pubKey.pem", "PUBLIC");
   printEVPKey(pubkey, "PUBLIC");

   EVP_PKEY *privk = read_pem_file("server_privKey.pem", "PRIVATE");
   printEVPKey(privk, "PRIVATE");
*/
   if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == 0)
   {
      perror("socket creation failed");
      exit(EXIT_FAILURE);
   }

   if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0)
   {
      perror("bind failed");
      exit(EXIT_FAILURE);
   }

   std::cout << "Server listening on port: " << port << std::endl;
   if (listen(listener, MAX_CLIENTS) < 0)
   {
      perror("error in listen");
      exit(EXIT_FAILURE);
   }
   // Initialize the set of active sockets
   fd_set master_set, read_set;
   FD_ZERO(&master_set);          // Clear the set
   FD_SET(listener, &master_set); // Add the server socket to the set (inizialmente c'è solo il server)

   int max_fd = listener;
   while (true)
   {
      read_set = master_set;

      if (select(max_fd + 1, &read_set, NULL, NULL, NULL) == -1)
      {
         perror("select");
         close(listener);
         exit(EXIT_FAILURE);
      }

      for (int ii = 0; ii <= max_fd; ii++)
      {
         if (FD_ISSET(ii, &read_set))
         {
            if (ii == listener)
            {
               sockaddr_in client_address;
               socklen_t client_address_len = sizeof(client_address);
               int client_socket = accept(listener, (struct sockaddr *)&client_address, &client_address_len);
               std::cout << "New connection from IP: " << inet_ntoa(client_address.sin_addr) << ", port: " << port << std::endl;

               if (client_socket < 0)
               {
                  perror("accept");
                  close(listener);
                  exit(EXIT_FAILURE);
               }

               // Add the new socket to the set
               FD_SET(client_socket, &master_set);
               if (client_socket > max_fd)
               {
                  max_fd = client_socket;
               }
            }
            else
            {
               memset(buffer, 0, sizeof(buffer));
               int byterec = recv(ii, buffer, BUFFER_SIZE, 0);
               std::cout << byterec << std::endl;
               if (byterec <= 0)
               {
                  close(ii);
                  FD_CLR(ii, &master_set); // rimuovere socket
               }
               else
               {
                  DEBUG_PRINT(("N° Byte received %d:", byterec));
                  // DEBUG_PRINT(("Received command from socket fd: %d", sd));
                  DEBUG_PRINT(("Buffer ricevut: %s", buffer));

                  std::string receivedData(buffer, buffer + byterec);
                  std::vector<std::string> splitData;

                  std::cout << "Mistico: " << receivedData[0] << std::endl;

                  /*size_t pos = 0;
                  while ((pos = receivedData.find("|")) != std::string::npos)
                  { // split the received data
                     std::string token = receivedData.substr(0, pos);
                     splitData.push_back(token);
                     receivedData.erase(0, pos + 1);
                  }*/

                  std::cout << "Splitted data: ";
                  for (auto a : splitData)
                     std::cout << a << std::endl;
                  std::cout << std::endl;

                  // Now you can access the split data using splitData[index]
                  // For example, splitData[0] will give you the first token before the first '|'
                  // splitData[1] will give you the second token between the first and second '|', and so on.
                  char choice;
                  char methodBuffer[BUFFER_SIZE];
                  if (receivedData[0] == '0')
                  {
                     std::cout << "Client requested register" << std::endl;
                     choice = '0';
                  }
                  else
                  {
                     std::cout << "PORCODDIO" << std::endl;
                  }
                  /*else if (method== '1')
                  {
                     choice = '1';
                     std::cout << "Client requested login" << std::endl;
                  }
                  else if (strcmp(method, "2") == 0)
                  {
                     choice = '2';
                     std::cout << "Client requested hello" << std::endl;
                  }
                  else if (strcmp(method, "3") == 0)
                  {
                     choice = '3';
                  }*/

                  if (choice == CODES::LOGIN)
                  { // login request
                     std::cout << "to do" << std::endl;
                  }
                  else if (choice == CODES::REGISTER)
                  {
                     // Register request
                     std::cout << "Client requested registration" << std::endl;
                     memset(buffer, 0, sizeof(buffer));
                     // TODO: Aggiungere il codice per la registrazione
                     int bytes_read = read(ii, buffer, BUFFER_SIZE);
                     if (bytes_read <= 0)
                     {
                        close(ii);
                        FD_CLR(ii, &master_set);
                     }
                     else
                     {
                        // TODO: function getOperation
                     }
                  }
                  else if (memcmp(buffer, "LIST", 4) == 0)
                  {
                     // TODO da implementare
                     std::cout << "Client requested list of files" << std::endl;
                  }
                  // TODO da fare altri comandi
                  else
                  {
                     std::cout << "Unknown request: " << buffer << std::endl;
                  }
               }
            }
         }
      }
   }
}
/*  da lavorarci
void Server::reportError(int sd, int index){
    if(index<0){ // if the user is not logged report error on plaintext
        send(sd, "ERR", 4, 0);
        return;
    }
    string cmd = "ERR";
    DEBUG_PRINT(("cmd: %s\n", cmd.c_str()));
    unsigned char* IV = nullptr;
    unsigned char* to_hashed = nullptr;
    unsigned char* MAC = nullptr;
    unsigned char* to_enc = nullptr;
    int msg_len = 0;
    int enc_len = 0;
    unsigned char * msg = createCiphertext(cmd, user_logged[index].id, user_logged[index].session_key,
                        &IV, &to_hashed, &MAC,user_logged[index].HMAC_key, &to_enc, &msg_len, &enc_len);
    if(IV!=nullptr)
        securefree(IV, IVLEN);
    if(to_hashed!=nullptr)
        securefree(to_hashed, IVLEN+enc_len+1);
    if(MAC!=nullptr)
        securefree(MAC, SHA256LEN);
    if(to_enc != nullptr)
        securefree(to_enc, cmd.length()+1);
    if(msg == nullptr){
        printf("Error in generating the error message\n");
    }

    send(sd,msg,msg_len,0);
    securefree(msg,msg_len);
}
*/
Server::~Server()
{
   EVP_PKEY_free(pubKey);
}
