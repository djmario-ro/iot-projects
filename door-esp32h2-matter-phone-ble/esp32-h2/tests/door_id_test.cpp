#include "../PersistentDoorId.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string>
struct FakeNvs {
 bool present=false,fail=false;uint32_t value=0;unsigned writes=0;
 bool isKey(const char* key){assert(std::string(key)=="door_id");return present;}
 uint32_t getUInt(const char*,uint32_t){return value;}
 size_t putUInt(const char* key,uint32_t v){assert(std::string(key)=="door_id");writes++;if(fail)return 0;present=true;value=v;return 4;}
};
int main(){
 FakeNvs p;unsigned calls=0;uint32_t id=0;
 auto random=[&](){return ++calls==1?0u:0xfedcba98u;};
 assert(loadPersistentDoorId(p,random,id));assert(id==0xfedcba98u&&calls==2&&p.writes==1);
 id=0;assert(loadPersistentDoorId(p,random,id));assert(id==0xfedcba98u&&calls==2&&p.writes==1);
 uint8_t bytes[4];encodeDoorId(id,bytes);assert(bytes[0]==0x98&&bytes[1]==0xba&&bytes[2]==0xdc&&bytes[3]==0xfe);
 p.value=0;assert(!loadPersistentDoorId(p,random,id));assert(calls==2&&p.writes==1);
 FakeNvs bad;bad.fail=true;id=0;assert(!loadPersistentDoorId(bad,random,id));assert(id==0);
 puts("PASS: missing-ID migration, zero rejection, restart persistence, no silent identity replacement, NVS write failure, 32-bit wire encoding");
}
