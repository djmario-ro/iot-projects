#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
using CHIP_ERROR=int;
constexpr int CHIP_NO_ERROR=0,CHIP_ERROR_INCORRECT_STATE=1,CHIP_ERROR_INVALID_ARGUMENT=2,CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND=3;
namespace chip {
using EndpointId=uint16_t;
struct CharSpan{const char* ptr=nullptr;size_t length=0;CharSpan()=default;CharSpan(const char*p,size_t n):ptr(p),length(n){}const char*data()const{return ptr;}size_t size()const{return length;}};
class PersistentStorageDelegate{public:virtual~PersistentStorageDelegate()=default;virtual int SyncGetKeyValue(const char*,void*,uint16_t&)=0;virtual int SyncSetKeyValue(const char*,const void*,uint16_t)=0;virtual int SyncDeleteKeyValue(const char*)=0;};
namespace DeviceLayer {
class DeviceInfoProvider {
public:
 struct UserLabelType{CharSpan label,value;};
 template<class T>struct Iterator{virtual~Iterator()=default;virtual size_t Count()=0;virtual bool Next(T&)=0;virtual void Release()=0;};
 using UserLabelIterator=Iterator<UserLabelType>;using FixedLabelIterator=Iterator<int>;using SupportedLocalesIterator=Iterator<int>;using SupportedCalendarTypesIterator=Iterator<int>;
 virtual~DeviceInfoProvider()=default;
 void SetStorageDelegate(PersistentStorageDelegate*p){mStorage=p;}
 virtual FixedLabelIterator*IterateFixedLabel(EndpointId)=0;virtual UserLabelIterator*IterateUserLabel(EndpointId)=0;
 virtual SupportedLocalesIterator*IterateSupportedLocales()=0;virtual SupportedCalendarTypesIterator*IterateSupportedCalendarTypes()=0;
 // Public wrappers expose protected storage hooks to this focused backend test.
 int put(EndpointId e,size_t i,const UserLabelType&v){return SetUserLabelAt(e,i,v);}
 int length(EndpointId e,size_t n){return SetUserLabelLength(e,n);}
 int erase(EndpointId e,size_t i){return DeleteUserLabelAt(e,i);}
protected:
 PersistentStorageDelegate*mStorage=nullptr;
 virtual int SetUserLabelAt(EndpointId,size_t,const UserLabelType&)=0;virtual int DeleteUserLabelAt(EndpointId,size_t)=0;
 virtual int SetUserLabelLength(EndpointId,size_t)=0;virtual int GetUserLabelLength(EndpointId,size_t&)=0;
};
}}
