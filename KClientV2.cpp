//
// Created by george on 16/11/2017.
//

#include "KClientV2.h"

KClientV2::KClientV2(unsigned p, unsigned g, unsigned logQ, const string &data, const string &u_serverIP,
                 unsigned u_serverPort, const string &t_serverIP, unsigned t_serverPort, bool verbose) {
    this->verbose=verbose;
    this->u_serverIP = u_serverIP;
    this->u_serverPort = u_serverPort;
    this->t_serverIP = t_serverIP;
    this->t_serverPort = t_serverPort;
    this->client_p = p;
    this->client_g = g;
    this->client_logQ = logQ;
    print("K-CLIENT");
    FHEcontext context(this->client_p - 1, this->client_logQ, this->client_p, this->client_g);
    activeContext = &context;
    this->client_context = &context;
    context.SetUpSIContext();
    FHESISecKey fhesiSecKey1(context);
    FHESIPubKey fhesiPubKey1(fhesiSecKey1);
    KeySwitchSI keySwitchSI1(fhesiSecKey1);
    FHESISecKey fhesiSecKeyT(context);
    KeySwitchSI keySwitchSIT(fhesiSecKey1, fhesiSecKeyT);
    this->fhesiSecKey = &fhesiSecKey1;
    this->fhesiPubKey = &fhesiPubKey1;
    this->keySwitchSI = &keySwitchSI1;
    this->fhesiSecKeyT = &fhesiSecKeyT;
    this->keySwitchSIT = &keySwitchSIT;
    print(context);
    //print(*this->fhesiPubKey);
    //print(*this->fhesiSecKey);
    //print(*this->keySwitchSI);
    //print(*this->fhesiSecKeyT);
    //print(*this->keySwitchSIT);
    this->connectToTServer();
    this->sendEncryptionParamToTServer();
    this->connectToUServer();
    this->sendEncryptionParamToUServer();
    LoadDataPolyX(this->loadeddata, this->labels, this->dim, data, *this->client_context);
    this->sendEncryptedDataToUServer();
    this->receiveResult();
}

void KClientV2::connectToTServer() {
    struct sockaddr_in t_server_address;
    if (this->t_serverSocket == -1) {
        this->t_serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (this->t_serverSocket < 0) {
            perror("ERROR ON TSERVER SOCKET CREATION");
            exit(1);
        } else {
            string message =
                    "Socket for TServer created successfully. File descriptor: " + to_string(this->t_serverSocket);
            print(message);
        }

    }
    t_server_address.sin_addr.s_addr = inet_addr(this->t_serverIP.c_str());
    t_server_address.sin_family = AF_INET;
    t_server_address.sin_port = htons(static_cast<uint16_t>(this->t_serverPort));

    if (connect(this->t_serverSocket, (struct sockaddr *) &t_server_address, sizeof(t_server_address)) < 0) {
        perror("ERROR. CONNECTION FAILED TO TSERVER");

    } else {
        print("KClientV2 CONNECTED TO TSERVER");

    }

}

void KClientV2::connectToUServer() {
    struct sockaddr_in u_server_address;
    if (this->u_serverSocket == -1) {
        this->u_serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (this->u_serverSocket < 0) {
            perror("ERROR ON USERVER SOCKET CREATION");
            exit(1);
        } else {
            string message =
                    "Socket for UServer created successfully. File descriptor: " + to_string(this->u_serverSocket);
            print(message);
        }

    }
    u_server_address.sin_addr.s_addr = inet_addr(this->u_serverIP.c_str());
    u_server_address.sin_family = AF_INET;
    u_server_address.sin_port = htons(static_cast<uint16_t>(this->u_serverPort));

    if (connect(this->u_serverSocket, (struct sockaddr *) &u_server_address, sizeof(u_server_address)) < 0) {
        perror("ERROR. CONNECTION FAILED TO USERVER");

    } else {
        print("KClientV2 CONNECTED TO USERVER");

    }

}

bool KClientV2::sendMessage(string message, int socket) {
    if (send(socket, message.c_str(), strlen(message.c_str()), 0) < 0) {
        perror("SEND FAILED.");
        return false;
    } else {
        this->log(socket, "<--- " + message);
        return true;
    }
}

bool KClientV2::sendStream(ifstream data, int socket) {
    streampos begin, end;
    begin = data.tellg();
    data.seekg(0, ios::end);
    end = data.tellg();
    streampos size = end - begin;
    uint32_t sizek = size;
    auto *memblock = new char[sizek];
    data.seekg(0, std::ios::beg);
    data.read(memblock, sizek);
    data.close();
    htonl(sizek);
    if (0 > send(socket, &sizek, sizeof(uint32_t), 0)) {
        perror("SEND FAILED.");
        return false;
    } else {
        this->log(socket, "<--- " + to_string(sizek));
        if (this->receiveMessage(socket, 7) == "SIZE-OK") {
            ssize_t r = (send(socket, memblock, static_cast<size_t>(size), 0));
            print(r); //for debugging
            if (r < 0) {
                perror("SEND FAILED.");
                return false;
            } else {
                return true;
            }
        } else {
            perror("SEND SIZE ERROR");
            return false;
        }
    }


}

string KClientV2::receiveMessage(const int &socket, int buffersize) {
    char buffer[buffersize];
    string message;
    if (recv(socket, buffer, static_cast<size_t>(buffersize), 0) < 0) {
        perror("RECEIVE FAILED");
    }
    message = buffer;
    message.erase(static_cast<unsigned long>(buffersize));
    this->log(socket, "---> " + message);
    return message;
}

void KClientV2::log(int socket, string message) {
    if(this->verbose){
    sockaddr address;
    socklen_t addressLength;
    sockaddr_in *addressInternet;
    string ip;
    int port;
    getpeername(socket, &address, &addressLength);
    addressInternet = (struct sockaddr_in *) &address;
    ip = inet_ntoa(addressInternet->sin_addr);
    port = addressInternet->sin_port;
    string msg = "[" + ip + ":" + to_string(port) + "] " + message;
    print(msg);
    }
}


ifstream KClientV2::pkCToStream() {
    ofstream filedat("pk.dat");
    Export(filedat, this->fhesiPubKey->GetRepresentation());
    return ifstream("pk.dat", ios::binary);
}

ifstream KClientV2::ksCToStream() {
    ofstream filedat("ksC.dat");
    Export(filedat, this->keySwitchSI->GetRepresentation());
    return ifstream("ksC.dat");
}

ifstream KClientV2::ksTToStream() {
    ofstream filedat("ksT.dat");
    Export(filedat, this->keySwitchSIT->GetRepresentation());
    return ifstream("ksT.dat");
}

ifstream KClientV2::skTToStream() {
    ofstream filedat("skT.dat");
    Export(filedat, this->fhesiSecKeyT->GetRepresentation());
    return ifstream("skT.dat");
}

ifstream KClientV2::contextToStream() {
    ofstream filedat("context.dat");
    this->client_context->ExportSIContext(filedat);
    return ifstream("context.dat");
}

ifstream KClientV2::encryptedDataToStream(const Ciphertext &ciphertext) {
    ofstream ofstream1("temp.dat");
    Export(ofstream1, ciphertext);
    return ifstream("temp.dat");
}

void KClientV2::sendEncryptionParamToTServer() {
    this->sendMessage("C-PK", this->t_serverSocket);
    string message = this->receiveMessage(this->t_serverSocket, 10);
    if (message != "T-PK-READY") {
        perror("ERROR IN PROTOCOL 2-STEP 1");
        return;
    }
    this->sendStream(this->pkCToStream(), this->t_serverSocket);
    string message1 = this->receiveMessage(this->t_serverSocket, 13);
    if (message1 != "T-PK-RECEIVED") {
        perror("ERROR IN PROTOCOL 2-STEP 2");
        return;
    }
    this->sendMessage("C-SMT", this->t_serverSocket);
    string message2 = this->receiveMessage(this->t_serverSocket, 11);
    if (message2 != "T-SMT-READY") {
        perror("ERROR IN PROTOCOL 2-STEP 3");
        return;
    }
    this->sendStream(this->ksTToStream(), this->t_serverSocket);
    string message3 = this->receiveMessage(this->t_serverSocket, 14);
    if (message3 != "T-SMT-RECEIVED") {
        perror("ERROR IN PROTOCOL 2-STEP 4");
        return;
    }
    this->sendMessage("C-SKT", this->t_serverSocket);
    string message4 = this->receiveMessage(this->t_serverSocket, 11);
    if (message4 != "T-SKT-READY") {
        perror("ERROR IN PROTOCOL 2-STEP 5");
        return;
    }
    this->sendStream(this->skTToStream(), this->t_serverSocket);
    string message5 = this->receiveMessage(this->t_serverSocket, 14);
    if (message5 != "T-SKT-RECEIVED") {
        perror("ERROR IN PROTOCOL 2-STEP 6");
        return;
    }
    this->sendMessage("C-CONTEXT",this->t_serverSocket);
    string message6 = this->receiveMessage(this->t_serverSocket, 9);
    if (message6 != "T-C-READY") {
        perror("ERROR IN PROTOCOL 2-STEP 7");
        return;
    }
    this->sendStream(this->contextToStream(),this->t_serverSocket);
    string message7 = this->receiveMessage(this->t_serverSocket, 12);
    if (message7 != "T-C-RECEIVED") {
        perror("ERROR IN PROTOCOL 2-STEP 8");
        return;
    }
    print("PROTOCOL 2 COMPLETED");
    close(this->t_serverSocket);
}

void KClientV2::sendEncryptionParamToUServer() {
    this->sendMessage("C-PK", this->u_serverSocket);
    string message = this->receiveMessage(this->u_serverSocket, 10);
    if (message != "U-PK-READY") {
        perror("ERROR IN PROTOCOL 1-STEP 1");
        return;
    }
    this->sendStream(this->pkCToStream(), this->u_serverSocket);
    string message1 = this->receiveMessage(this->u_serverSocket, 13);
    if (message1 != "U-PK-RECEIVED") {
        perror("ERROR IN PROTOCOL 1-STEP 2");
        return;
    }
    this->sendMessage("C-SM", this->u_serverSocket);
    string message2 = this->receiveMessage(this->u_serverSocket, 10);
    if (message2 != "U-SM-READY") {
        perror("ERROR IN PROTOCOL 1-STEP 3");
        return;
    }
    this->sendStream(this->ksCToStream(), this->u_serverSocket);
    string message3 = this->receiveMessage(this->u_serverSocket, 13);
    if (message3 != "U-SM-RECEIVED") {
        perror("ERROR IN PROTOCOL 1-STEP 4");
        return;
    }
    this->sendMessage("C-CONTEXT",this->u_serverSocket);
    string message4 = this->receiveMessage(this->u_serverSocket, 9);
    if (message4 != "U-C-READY") {
        perror("ERROR IN PROTOCOL 1-STEP 5");
        return;
    }
    this->sendStream(this->contextToStream(),this->u_serverSocket);
    string message5 = this->receiveMessage(this->u_serverSocket, 12);
    if (message5 != "U-C-RECEIVED") {
        perror("ERROR IN PROTOCOL 2-STEP 8");
        return;
    }
    print("PROTOCOL 1 COMPLETED");
    close(this->u_serverSocket);
    this->u_serverSocket=-1;
}

void KClientV2::sendEncryptedDataToUServer() {
    this->connectToUServer();
    this->sendMessage("C-DA", this->u_serverSocket);
    string message = this->receiveMessage(this->u_serverSocket, 12);
    if (message != "U-DATA-READY") {
        perror("ERROR IN PROTOCOL 3-STEP 1");
        return;
    }
    for (unsigned i = 0; i < this->loadeddata.size(); i++) {
        log(this->u_serverSocket, "<--- POINT-" + to_string(i));
        this->sendMessage("C-DATA-P", this->u_serverSocket);
        string message1 = this->receiveMessage(this->u_serverSocket, 14);
        if (message1 != "U-DATA-P-READY") {
            perror("ERROR IN PROTOCOL 3-STEP 2");
            return;
        }
        Ciphertext ciphertext(*this->fhesiPubKey);
        Plaintext plaintext(*this->client_context, this->loadeddata[i]);
        this->fhesiPubKey->Encrypt(ciphertext, plaintext);
        ifstream cipher = this->encryptedDataToStream(ciphertext);
        std::string buffer((std::istreambuf_iterator<char>(cipher)), std::istreambuf_iterator<char>());
        cipher.close();
        hash<string> str_hash;
        uint32_t indext= (uint32_t)str_hash(buffer);
        this->encrypted_data_hash_table[indext] = this->loadeddata[i];
        this->sendStream(this->encryptedDataToStream(ciphertext), this->u_serverSocket);
        string message2 = this->receiveMessage(this->u_serverSocket, 17);
        if (message2 != "U-DATA-P-RECEIVED") {
            perror("ERROR IN PROTOCOL 3-STEP 3");
            return;
        }
    }
    this->sendMessage("C-DATA-E", this->u_serverSocket);
    string message1 = this->receiveMessage(this->u_serverSocket, 15);
    if (message1 != "U-DATA-RECEIVED") {
        perror("ERROR IN PROTOCOL 3-STEP 4");
        return;
    }
    print("PROTOCOL 3 COMPLETED");

}

void KClientV2::receiveResult() {
    print("WAITING FOR KMEANS RESULTS");
    string message=this->receiveMessage(this->u_serverSocket,8);
    if (message != "U-RESULT") {
        perror("ERROR IN PROTOCOL 8-STEP 1");
        return;
    }
    this->sendMessage("K-READY",this->u_serverSocket);
    for(unsigned i=0;i<this->encrypted_data_hash_table.size();i++){
        string message1=this->receiveMessage(this->u_serverSocket,3);
        if (message1 != "U-P") {
            perror("ERROR IN PROTOCOL 8-STEP 2");
            return;
        }
        this->sendMessage("U-P-R",this->u_serverSocket);
        uint32_t hash_value;
        auto *data = (char *) &hash_value;
        if (recv(this->u_serverSocket, data, sizeof(uint32_t), 0) < 0) {
            perror("RECEIVE IDENTITY ERROR. ERROR IN PROTOCOL 8-STEP 3");
        }
        ntohl(hash_value);
        this->log(this->u_serverSocket, "--> POINT ID: " + to_string(hash_value));
        this->sendMessage("P-I-R",this->u_serverSocket);
        uint32_t index;
        auto *data1 = (char *) &index;
        if (recv(this->u_serverSocket, data1, sizeof(uint32_t), 0) < 0) {
            perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 8-STEP 4");
        }
        ntohl(index);
        this->log(this->u_serverSocket, "--> INDEX: " + to_string(index));
        unsigned clusterindex=index;
        this->results[hash_value]=clusterindex;
        this->sendMessage("P-CI-R",this->u_serverSocket);
    }
    string message2=this->receiveMessage(this->u_serverSocket,10);
    if (message2 != "U-RESULT-E") {
        perror("ERROR IN PROTOCOL 8-STEP 5");
        return;
    }
    this->sendMessage("K-END",this->u_serverSocket);
    close(this->u_serverSocket);
    this->u_serverSocket=-1;
    print("--------------------RESULTS--------------------");
    for (auto &iter : this->encrypted_data_hash_table) {
        cout << "Point ID: " << iter.first << " Point: " << iter.second <<" Cluster: "<< this->results[iter.first]<< endl;
    }

}