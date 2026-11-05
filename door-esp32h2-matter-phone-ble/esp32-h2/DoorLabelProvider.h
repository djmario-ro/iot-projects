#pragma once
#include <platform/DeviceInfoProvider.h>
#include <lib/support/CHIPMem.h>
#include <new>
#include <stdio.h>
#include <string.h>

// Arduino's CONFIG_NONE_DEVICE_INFO_PROVIDER omits ESP32DeviceInfoProvider from
// the prebuilt library. Supply the standard four-entry UserLabel backing store.
class DoorLabelProvider final:public chip::DeviceLayer::DeviceInfoProvider {
 struct Record { uint8_t labelSize,valueSize;char label[16],value[16]; };
 static void storageKey(char out[24],chip::EndpointId endpoint,int index){snprintf(out,24,"dkul/%u/%d",unsigned(endpoint),index);}
 CHIP_ERROR read(chip::EndpointId endpoint,size_t index,Record &record){
  if(!mStorage)return CHIP_ERROR_INCORRECT_STATE;
  char key[24];storageKey(key,endpoint,int(index));uint16_t size=sizeof(record);
  CHIP_ERROR err=mStorage->SyncGetKeyValue(key,&record,size);
  if(err!=CHIP_NO_ERROR)return err;
  return size==sizeof(record)&&record.labelSize<=16&&record.valueSize<=16?CHIP_NO_ERROR:CHIP_ERROR_INVALID_ARGUMENT;
 }
 class Labels final:public UserLabelIterator {
  DoorLabelProvider &owner;chip::EndpointId endpoint;size_t count=0,index=0;Record record{};
 public:
  Labels(DoorLabelProvider &p,chip::EndpointId e):owner(p),endpoint(e){if(owner.GetUserLabelLength(e,count)!=CHIP_NO_ERROR)count=0;}
  size_t Count()override{return count;}
  bool Next(UserLabelType &item)override{
   if(index>=count||owner.read(endpoint,index++,record)!=CHIP_NO_ERROR)return false;
   item.label=chip::CharSpan(record.label,record.labelSize);item.value=chip::CharSpan(record.value,record.valueSize);return true;
  }
  void Release()override{chip::Platform::Delete(this);}
 };
public:
 FixedLabelIterator* IterateFixedLabel(chip::EndpointId)override{return nullptr;}
 SupportedLocalesIterator* IterateSupportedLocales()override{return nullptr;}
 SupportedCalendarTypesIterator* IterateSupportedCalendarTypes()override{return nullptr;}
 UserLabelIterator* IterateUserLabel(chip::EndpointId e)override{return chip::Platform::New<Labels>(*this,e);}
protected:
 CHIP_ERROR SetUserLabelAt(chip::EndpointId endpoint,size_t index,const UserLabelType &item)override{
  if(!mStorage)return CHIP_ERROR_INCORRECT_STATE;
  if(index>=4||item.label.size()>16||item.value.size()>16)return CHIP_ERROR_INVALID_ARGUMENT;
  Record record{};record.labelSize=item.label.size();record.valueSize=item.value.size();
  if(record.labelSize)memcpy(record.label,item.label.data(),record.labelSize);
  if(record.valueSize)memcpy(record.value,item.value.data(),record.valueSize);
  char key[24];storageKey(key,endpoint,int(index));return mStorage->SyncSetKeyValue(key,&record,sizeof(record));
 }
 CHIP_ERROR DeleteUserLabelAt(chip::EndpointId endpoint,size_t index)override{
  if(!mStorage)return CHIP_ERROR_INCORRECT_STATE;
  char key[24];storageKey(key,endpoint,int(index));CHIP_ERROR err=mStorage->SyncDeleteKeyValue(key);
  return err==CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND?CHIP_NO_ERROR:err;
 }
 CHIP_ERROR SetUserLabelLength(chip::EndpointId endpoint,size_t count)override{
  if(!mStorage)return CHIP_ERROR_INCORRECT_STATE;if(count>4)return CHIP_ERROR_INVALID_ARGUMENT;
  uint8_t value=count;char key[24];storageKey(key,endpoint,-1);return mStorage->SyncSetKeyValue(key,&value,sizeof(value));
 }
 CHIP_ERROR GetUserLabelLength(chip::EndpointId endpoint,size_t &count)override{
  if(!mStorage)return CHIP_ERROR_INCORRECT_STATE;
  uint8_t value=0;uint16_t size=1;char key[24];storageKey(key,endpoint,-1);
  CHIP_ERROR err=mStorage->SyncGetKeyValue(key,&value,size);
  if(err==CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND){count=0;return CHIP_NO_ERROR;}
  if(err!=CHIP_NO_ERROR)return err;
  if(size!=1||value>4)return CHIP_ERROR_INVALID_ARGUMENT;count=value;return CHIP_NO_ERROR;
 }
};
