#include "../DoorLabelProvider.h"
#include <map>
#include <string>
#include <vector>
#include <assert.h>
struct Storage:chip::PersistentStorageDelegate{
 std::map<std::string,std::vector<uint8_t>> values;bool fail=false;
 int SyncGetKeyValue(const char*k,void*out,uint16_t&n)override{auto i=values.find(k);if(i==values.end())return CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;if(n<i->second.size())return CHIP_ERROR_INVALID_ARGUMENT;n=i->second.size();memcpy(out,i->second.data(),n);return 0;}
 int SyncSetKeyValue(const char*k,const void*in,uint16_t n)override{if(fail)return CHIP_ERROR_INCORRECT_STATE;auto p=static_cast<const uint8_t*>(in);values[k]=std::vector<uint8_t>(p,p+n);return 0;}
 int SyncDeleteKeyValue(const char*k)override{return values.erase(k)?0:CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;}
};
int main(){
 Storage store;DoorLabelProvider p;
 assert(p.length(1,0)==CHIP_ERROR_INCORRECT_STATE);
 p.SetStorageDelegate(&store);
 auto*empty=p.IterateUserLabel(1);assert(empty&&empty->Count()==0);empty->Release();
 chip::DeviceLayer::DeviceInfoProvider::UserLabelType label{chip::CharSpan("D0abcdefghijklm",15),chip::CharSpan("0123456789abcdef",16)};
 assert(p.length(1,4)==0);
 for(unsigned i=0;i<4;i++)assert(p.put(1,i,label)==0);
 assert(p.length(1,5)==CHIP_ERROR_INVALID_ARGUMENT);assert(p.put(1,4,label)==CHIP_ERROR_INVALID_ARGUMENT);
 DoorLabelProvider restarted;restarted.SetStorageDelegate(&store);
 auto*it=restarted.IterateUserLabel(1);assert(it&&it->Count()==4);chip::DeviceLayer::DeviceInfoProvider::UserLabelType got;
 for(unsigned i=0;i<4;i++){assert(it->Next(got));assert(std::string(got.label.data(),got.label.size())=="D0abcdefghijklm");assert(got.value.size()==16);}
 assert(!it->Next(got));it->Release();
 assert(restarted.length(1,0)==0);for(unsigned i=0;i<4;i++)assert(restarted.erase(1,i)==0);assert(restarted.erase(1,0)==0);
 store.fail=true;assert(p.length(1,1)==CHIP_ERROR_INCORRECT_STATE);
 puts("PASS: unbound storage failure, empty/new storage, four persisted labels, restart read-back, constraints, erase, write errors");
}
