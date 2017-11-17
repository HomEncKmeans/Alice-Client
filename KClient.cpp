//
// Created by george on 16/11/2017.
//

#include "KClient.h"

KClient::KClient(unsigned p, unsigned g, unsigned logQ,const string &data, const string &u_serverIP, unsigned u_serverPort,const string &t_serverIP,unsigned t_serverPort) {
    this->u_serverIP=u_serverIP;
    this->u_serverPort=u_serverPort;
    this->t_serverIP =t_serverIP;
    this->t_serverPort =t_serverPort;
    this->client_p=p;
    this->client_g=g;
    this->client_logQ=logQ;
    print("K-CLIENT");
    FHEcontext context(this->client_p-1,this->client_logQ, this->client_p, this->client_g);
    activeContext=&context;
    this->client_context=&context;
    context.SetUpSIContext();
    FHESISecKey fhesiSecKey1(context);
    FHESIPubKey fhesiPubKey1(fhesiSecKey1);
    KeySwitchSI keySwitchSI1(fhesiSecKey1);
    FHESISecKey fhesiSecKeyT(context);
    KeySwitchSI keySwitchSIT(fhesiSecKey1,fhesiSecKeyT);
    this->fhesiSecKey = &fhesiSecKey1;
    this->fhesiPubKey = &fhesiPubKey1;
    this->keySwitchSI = &keySwitchSI1;
    this->fhesiSecKeyT = &fhesiSecKeyT;
    this->keySwitchSIT = &keySwitchSIT;
    print(*this->fhesiPubKey);
    print(*this->fhesiSecKey);
    print(*this->keySwitchSI);
    print(*this->fhesiSecKeyT);
    print(*this->keySwitchSIT);
    this->connectToTServer();
    this->connectToUServer();
    this->sendEncryptionParamToTServer();
    //this->sendEncryptionParamU(this->addressU,this->portU);
    //this->sendEncryptionParamT(this->addressT,this->portT);
    //LoadDataPolyX(this->loadeddata,this->labels,this->dim,data,*this->client_context);
    //print(this->loadeddata[0]);
    //this->sendEncryptedData(this->addressU,this->portU);
}

void KClient::connectToTServer() {
    struct sockaddr_in t_server_address;
    if(this->t_serverSocket == -1){
        this->t_serverSocket = socket(AF_INET , SOCK_STREAM , 0);
        if (this->t_serverSocket<0){
            perror("ERROR ON TSERVER SOCKET CREATION");
            exit(1);
        }else{
            string message = "Socket for TServer created successfully. File descriptor: "+to_string(this->t_serverSocket);
            print(message);
        }

    }
    t_server_address.sin_addr.s_addr = inet_addr( this->t_serverIP.c_str() );
    t_server_address.sin_family = AF_INET;
    t_server_address.sin_port = htons(static_cast<uint16_t>(this->t_serverPort));

    if (connect(this->t_serverSocket,(struct sockaddr *)&t_server_address,sizeof(t_server_address)) < 0)
    {
        perror("ERROR. CONNECTION FAILED TO TSERVER");

    } else{
        print("KCLIENT CONNECTED TO TSERVER");

    }

}

void KClient::connectToUServer() {
    struct sockaddr_in u_server_address;
    if(this->u_serverSocket == -1){
        this->u_serverSocket = socket(AF_INET , SOCK_STREAM , 0);
        if (this->u_serverSocket<0){
            perror("ERROR ON USERVER SOCKET CREATION");
            exit(1);
        }else{
            string message = "Socket for UServer created successfully. File descriptor: "+to_string(this->u_serverSocket);
            print(message);
        }

    }
    u_server_address.sin_addr.s_addr = inet_addr( this->u_serverIP.c_str() );
    u_server_address.sin_family = AF_INET;
    u_server_address.sin_port = htons(static_cast<uint16_t>(this->u_serverPort));

    if (connect(this->u_serverSocket,(struct sockaddr *)&u_server_address,sizeof(u_server_address)) < 0)
    {
        perror("ERROR. CONNECTION FAILED TO USERVER");

    } else{
        print("KCLIENT CONNECTED TO USERVER");

    }

}

bool KClient::sendMessage(string message, int socket) {
    if( send(socket , message.c_str() , strlen( message.c_str() ) , 0) < 0){
        perror("SEND FAILED.");
        return false;
    }else{
        this->log(socket,"<--- "+message);
        return true;
    }
}

bool KClient::sendStream(ifstream data, int socket) {
    streampos begin,end;
    begin =data.tellg();
    data.seekg(0,ios::end);
    end=data.tellg();
    streampos size = end-begin;
    streampos *sizeref = &size;
    print(size);
    auto * memblock = new char [size];
    data.seekg (0, std::ios::beg);
    data.read (memblock, size);
    data.close();

    if(0 > send(socket, sizeref, sizeof(size), 0)){
        perror("SEND FAILED.");
        return false;
    }else {
        if (send(socket, memblock, static_cast<size_t>(size), 0) < 0) {
            perror("SEND FAILED.");
            return false;
        } else {
            return true;
        }
    }


}

string KClient::receiveMessage(const int &socket, int buffersize) {
    char buffer[buffersize];
    string message;
    if(recv(socket, buffer, static_cast<size_t>(buffersize), 0) < 0){
        perror("RECEIVE FAILED");
    }
    message=buffer;
    this->log(socket,"---> "+message);
    return message;
}

void KClient::log(int socket, string message){
    sockaddr address;
    socklen_t addressLength;
    sockaddr_in *addressInternet;
    string ip;
    int port;
    getpeername(socket, &address, &addressLength);
    addressInternet = (struct sockaddr_in *) &address;
    ip = inet_ntoa(addressInternet->sin_addr);
    port = addressInternet->sin_port;
    string msg = "["+ip+":"+to_string(port)+"] "+message;
    print(msg);
}


ifstream KClient::pkCToStream(){
    ofstream filedat("pk.dat");
    Export(filedat,this->fhesiPubKey->GetRepresentation());
    return ifstream("pk.dat",ios::binary);
}

ifstream KClient::ksCToStream() {
    ofstream filedat("ksC.dat");
    Export(filedat,this->keySwitchSI->GetRepresentation());
    return ifstream("ksC.dat");
}

ifstream KClient::ksTToStream() {
    ofstream filedat("ksT.dat");
    Export(filedat,this->keySwitchSIT->GetRepresentation());
    return ifstream("ksT.dat");
}

ifstream KClient::skTToStream() {
    ofstream filedat("skT.dat");
    Export(filedat,this->fhesiSecKeyT->GetRepresentation());
    return ifstream("skT.dat");
}

void KClient::sendEncryptionParamToTServer() {
    this->sendMessage("C-PK",this->t_serverSocket);
    string message = this->receiveMessage(this->t_serverSocket);
    if(message!="T-PK-READY"){
        perror("ERROR IN PROTOCOL 2-STEP 1");
        return;
    }
    this->sendStream(this->pkCToStream(),this->t_serverSocket);
    string message1= this->receiveMessage(this->t_serverSocket);
    if(message1!="T-PK-RECEIVED"){
        perror("ERROR IN PROTOCOL 2-STEP 2");
        return;
    }
    this->sendMessage("C-SMT",this->t_serverSocket);
    string message2 = this->receiveMessage(this->t_serverSocket);
    if(message2!="T-SMT-READY"){
        perror("ERROR IN PROTOCOL 2-STEP 3");
        return;
    }
    this->sendStream(this->ksTToStream(),this->t_serverSocket);
    string message3 = this->receiveMessage(this->t_serverSocket);
    if(message3!="T-SMT-RECEIVED"){
        perror("ERROR IN PROTOCOL 2-STEP 4");
        return;
    }
    this->sendMessage("C-SKT",this->t_serverSocket);
    string message4 = this->receiveMessage(this->t_serverSocket);
    if(message4!="T-SKT-READY"){
        perror("ERROR IN PROTOCOL 2-STEP 5");
        return;
    }
    this->sendStream(this->skTToStream(),this->t_serverSocket);
    string message5 = this->receiveMessage(this->t_serverSocket);
    if(message5!="T-SKT-RECEIVED"){
        perror("ERROR IN PROTOCOL 2-STEP 6");
        return;
    }
    print("PROTOCOL 2 COMPLETED");
    close(this->t_serverSocket);
}
