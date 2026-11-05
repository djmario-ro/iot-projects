#include "../ReaderSettings.h"
#include <assert.h>
#include <string>
#include <stdio.h>
int main(){
 const std::string publicKey="BGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUTYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=";
 char name[30];uint8_t key[65];
 for(std::string n:{std::string("A"),std::string("Door-204"),std::string(29,'x')}){
  char size[3];snprintf(size,sizeof(size),"%02x",unsigned(n.size()));
  std::string payload="1"+std::string(size)+n+publicKey;
  assert(payload.size()<=120);
  assert(ReaderSettings::decode(payload.data(),payload.size(),name,key));assert(n==name);assert(key[0]==4&&key[1]==0x6b&&key[64]==0xf5);
  assert(!ReaderSettings::decode(payload.data(),payload.size()-1,name,key));
  payload[0]='2';assert(!ReaderSettings::decode(payload.data(),payload.size(),name,key));
 }
 assert(!ReaderSettings::validName("",0));assert(!ReaderSettings::validName("bad\n",4));
 puts("Reader configuration decoder tests passed");
}
