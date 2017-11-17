//
// Created by george on 7/11/2017.
//

#include "Client.h"

/**
    Connect to a host on a certain port number
*/

using namespace std;

Client::Client(unsigned p, unsigned g, unsigned logQ,const string &data, const string &addressU, unsigned portU,const string &addressT,unsigned portT) {
    this->addressT=addressT;
    this->addressU=addressU;
    this->portT =portT;
    this->portU =portU;
    this->client_p=p;
    this->client_g=g;
    this->client_logQ=logQ;
    this->sock=-1;
    FHEcontext context(this->client_p-1,this->client_logQ, this->client_p, this->client_g);
    activeContext=&context;
    this->client_context=&context;
    context.SetUpSIContext();
    //print("Cryptographic context:");
    //print(context);
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
    this->sendEncryptionParamU(this->addressU,this->portU);
    //this->sendEncryptionParamT(this->addressT,this->portT);
    //LoadDataPolyX(this->loadeddata,this->labels,this->dim,data,*this->client_context);
    //print(this->loadeddata[0]);
    //this->sendEncryptedData(this->addressU,this->portU);
}


int Client::conn( const string &address, int port)
{
    //create socket if it is not already created
    if(sock == -1)
    {
        //Create socket
        sock = socket(AF_INET , SOCK_STREAM , 0);
        if (sock == -1)
        {
            perror("Could not create socket");
        }

        cout<<"Socket created\n";
    }

    server.sin_addr.s_addr = inet_addr( address.c_str() );


    server.sin_family = AF_INET;
    server.sin_port = htons( port );

    //Connect to remote server

    if (connect(sock,(struct sockaddr *)&server,sizeof(server)) < 0)
    {
        perror("Connection Failed. Error");
        return 1;
    }
    print("Connected");
    return 0;
}


bool Client::sendData(string data)
{
    if( send(sock , data.c_str() , strlen( data.c_str() ) , 0) < 0)
    {
        perror("Send failed : ");
        return false;
    } else{
        print(strlen(data.c_str()));
        cout<<"Sending: "<<data<<endl;
        return true;
    }

}

/**
    Receive data from the connected host
*/
string Client::receive(int size=512)
{
    char buffer[size];
    string reply;

    //Receive a reply from the server
    if( recv(sock , buffer , sizeof(buffer) , 0) < 0)
    {
        puts("recv failed");
    }

    reply = buffer;
    return reply;
}


bool Client::sendEncryptionParamU(string address, int port){
    bool flag=false;
    this->conn(address,port);
    this->sendData("C-PK");
    if(this->receive(512)=="U-PK-READY"){
        print("U-PK-READY");
        ifstream pkstream=this->pkCToStream();
        this->sendStream(pkstream);
        if(this->receive(512)==("U-PK-RECEIVED")){
            print("U-PK-RECEIVED");
            this->sendData("C-SM");
            if(this->receive(512)=="U-SM-READY"){
                ifstream ksC = this->ksCToStream();
                this->sendStream(ksC);
                if(this->receive(512)=="U-SM-RECEIVED"){
                 flag=true;
                }
            } else{
                perror("UNTRUSTED SERVER SM ERROR");
            }
        } else{
            perror("ERROR SENDING PK");
        }
    } else{
        perror("UNTRUSTED SERVER ERROR : ");
    }
    return flag;

}

bool Client::sendEncryptionParamT(string address, int port){
    bool flag=false;
    this->conn(address,port);
    this->sendData("C-PK");
    if(this->receive(512)=="T-PK-READY"){
        ifstream pkstream=this->pkCToStream();
        this->sendStream(pkstream);
        if(this->receive(512)==("T-PK-RECEIVED")){
            this->sendData("C-SMT");
            if(this->receive(512)=="T-SMT-READY"){
                ifstream ksT = this->ksTToStream();
                this->sendStream(ksT);
                if(this->receive(512)=="T-SMT-RECEIVED"){
                    this->sendData("C-SKT");
                    if(this->receive(512)=="T-SKT-READY") {
                        ifstream skT=this->skTToStream();
                        this->sendStream(skT);
                        if(this->receive(512)=="T-SKT-READY") {
                            flag=true;
                        }
                    } else{
                        perror("TRUSTED SERVER SKT ERROR");
                    }
                }
            } else{
                perror("TRUSTED SERVER SM ERROR");
            }
        } else{
            perror("ERROR SENDING PK");
        }
    } else{
        perror("TRUSTED SERVER ERROR : ");
    }
    return flag;

}

ifstream Client::pkCToStream(){
    ofstream filedat("pk.dat");
    Export(filedat,this->fhesiPubKey->GetRepresentation());
    return ifstream("pk.dat",ios::binary);
}

bool Client::sendEncryptedData(string address, int port) {
    this->conn(address,port);
    this->sendData("C-DATA");
    if(this->receive(512)=="U-DATA-READY"){
        for(unsigned i=0;i<this->loadeddata.size();i++){
            print("Sending Point: "+to_string(i));
            Ciphertext ciphertext(*this->fhesiPubKey);
            print(this->loadeddata[i]);
            Plaintext plaintext(*this->client_context,this->loadeddata[i]);
            this->fhesiPubKey->Encrypt(ciphertext,plaintext);
            print(ciphertext);
            ifstream cipher= this->encryptedDataToStream(ciphertext);
            std::string buffer((std::istreambuf_iterator<char>(cipher)),std::istreambuf_iterator<char>());
            print(buffer);
            hash<string> str_hash;
            this->encrypted_data_hash_table[str_hash(buffer)]=this->loadeddata[i];

            this->sendStream(cipher);
            this->sendData("C-DATA-P");
            string message = this->receive(512);
            if(message!="U-DATA-R"){
                perror("ERROR on DATA TRANSMISSION:");
                break;
            }else{
                print(message);
            }

        }
    for (auto &iter : this->encrypted_data_hash_table) {
        print(iter.first);
        print(iter.second);

    }
        this->sendData("C-DATA-TF");
    }
}

ifstream Client::encryptedDataToStream(const Ciphertext &ciphertext) {
    ofstream ofstream1("temp.dat");
    Export(ofstream1,ciphertext);
    return ifstream("temp.dat");
}


bool Client::sendStream(ifstream &data) {
    //Send some data
    streampos begin,end;
    begin =data.tellg();
    data.seekg(0,ios::end);
    end=data.tellg();
    streampos size = end-begin;
    streampos *sizeref = &size;
    print(size);
    char * memblock = new char [size];
    data.seekg (0, std::ios::beg);
    data.read (memblock, size);
    data.close();

    if(send(sock, sizeref, sizeof(size), 0) < 0){
        perror("Send failed : ");
        return false;
    }
    if( send(sock , memblock , size , 0) < 0)
    {
        perror("Send failed : ");
        return false;
    } else{
        return true;
    }


}

ifstream Client::ksCToStream() {
    ofstream filedat("ksC.dat");
    Export(filedat,this->keySwitchSI->GetRepresentation());
    return ifstream("ksC.dat");
}

ifstream Client::ksTToStream() {
    ofstream filedat("ksT.dat");
    Export(filedat,this->keySwitchSIT->GetRepresentation());
    return ifstream("ksT.dat");
}

ifstream Client::skTToStream() {
    ofstream filedat("skT.dat");
    Export(filedat,this->fhesiSecKeyT->GetRepresentation());
    return ifstream("skT.dat");
}
