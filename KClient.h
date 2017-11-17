//
// Created by george on 16/11/2017.
//

#ifndef KCLIENT_KCLIENT_H
#define KCLIENT_KCLIENT_H

#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "FHE-SI.h"
#include "Serialization.h"
#include "clientfhesiutils.h"
#include "unistd.h"
using namespace std;

class KClient {

private:
    string u_serverIP;
    int u_serverPort;
    int u_serverSocket=-1;
    string t_serverIP;
    int t_serverPort;
    int t_serverSocket=-1;


    unsigned client_p;
    unsigned client_g;
    unsigned client_logQ;
    FHEcontext *client_context;
    FHESISecKey *fhesiSecKey;
    FHESIPubKey *fhesiPubKey;
    KeySwitchSI *keySwitchSI;
    FHESISecKey *fhesiSecKeyT;
    KeySwitchSI *keySwitchSIT;
    ifstream pkCToStream();
    ifstream ksCToStream();
    ifstream ksTToStream();
    ifstream skTToStream();


    void connectToUServer();
    void connectToTServer();

public:
    KClient(unsigned, unsigned, unsigned,const string &,const string&,unsigned ,const string &, unsigned);
    bool sendMessage(string, int socket);
    bool sendStream(ifstream, int);
    string receiveMessage(const int &,int buffersize=64);
    void log(int,string);
    void sendEncryptionParamToTServer();
    void sendEncryptionParamToUServer();
    void sendEncryptedDataToUServer();
};


#endif //KCLIENT_KCLIENT_H
