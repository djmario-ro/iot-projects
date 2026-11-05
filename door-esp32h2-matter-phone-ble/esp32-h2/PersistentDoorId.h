#pragma once
#include <stdint.h>

// Generate only for a missing NVS entry. Never silently replace a corrupt identity.
template<class Storage,class Random>
bool loadPersistentDoorId(Storage &storage,Random random,uint32_t &id){
 if(storage.isKey("door_id")){
  uint32_t saved=storage.getUInt("door_id",0);
  if(!saved)return false;
  id=saved;return true;
 }
 uint32_t generated;
 do{generated=random();}while(!generated);
 if(storage.putUInt("door_id",generated)!=sizeof(uint32_t))return false;
 id=generated;return true;
}
inline void encodeDoorId(uint32_t id,uint8_t out[4]){
 for(unsigned i=0;i<4;i++)out[i]=uint8_t(id>>(8*i));
}
