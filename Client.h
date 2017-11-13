//
// Created by george on 7/11/2017.
//

#ifndef KCLIENT_CLIENT_H
#define KCLIENT_CLIENT_H

#include<iostream>    //cout
#include<cstring>    //strlen
#include<string>  //string
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
#include <FHEContext.h> //
#include <FHE-SI.h>
#include "clientfhesiutils.h"
#include <sstream>
#include "streambuf"
#include "SerializeObjects.h"
#include "openssl/sha.h"
#include <functional>
#include <map>
#include "Serialization.h"


using namespace std;
//FHESISecKey secKey(*activeContext);
//FHESIPubKey pubKey(secKey);
//KeySwitchSI switchSI(secKey);

class Client {

private:
    int sock;
    string addressU;
    string addressT;
    int portU;
    int portT;
    struct sockaddr_in server;
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
    ifstream encryptedDataToStream(const Ciphertext &);
    vector<ZZ_pX> loadeddata;
    vector<ZZ_p> labels;
    map<size_t,ZZ_pX > encrypted_data_hash_table;
    unsigned dim;
public:
    Client(unsigned, unsigned, unsigned,const string &,const string&,unsigned ,const string &, unsigned);
    int conn(const string &addrr, int);
    bool sendData(string data);
    bool sendStream(ifstream &data);
    string receive(int);
    bool sendEncryptionParamU(string,int);
    bool sendEncryptionParamT(string,int);
    bool sendEncryptedData(string,int);


};

#endif //KCLIENT_CLIENT_H
