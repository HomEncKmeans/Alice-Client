//
// Created by george on 8/11/2017.
//

#include "KClient.h"

int main(){

    unsigned p=23;
    unsigned g=7;
    unsigned logQ=117;
    KClient client(p,g,logQ,"../sample.dat","127.0.0.1",5001,"127.0.0.1",5002);
    //client.sendEncryptedData();
    //client.sendPublicKey("127.0.0.1",5001);
    //client.conn("127.0.0.1",5001);
    //client.sendData("Hello  from Client");
    //std:cout<<client.receive(512)<<std::endl;



}