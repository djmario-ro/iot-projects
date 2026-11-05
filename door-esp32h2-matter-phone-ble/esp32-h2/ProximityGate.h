#pragma once
#include <stdint.h>
#include <algorithm>

// Independent from BLE/Arduino so the real filtering/rearm logic can be tested.
class ProximityGate {
  int values[5]{}; unsigned count=0,index=0;
  uint32_t lastSample=0,strongSince=0,weakSince=0,lastAttempt=0;
  bool strong=false,weak=false,attempted=false,latched=false;
public:
  int threshold=-50,filtered=-127;
  void resetSamples(){count=index=0;strong=weak=false;filtered=-127;}
  bool sample(int rssi,uint32_t now){
    if(rssi < -110 || rssi > -10)return false;
    if(count && uint32_t(now-lastSample)>1500)resetSamples();
    lastSample=now;values[index]=rssi;index=(index+1)%5;if(count<5)count++;
    int sorted[5];std::copy(values,values+count,sorted);std::sort(sorted,sorted+count);
    filtered=sorted[count/2];
    if(count<5){strong=weak=false;return true;}
    if(filtered>=threshold){if(!strong)strongSince=now;strong=true;}else strong=false;
    if(filtered<threshold-12){if(!weak)weakSince=now;weak=true;}else weak=false;
    if(latched && weak && uint32_t(now-weakSince)>=1000)latched=false;
    return true;
  }
  bool near(uint32_t now) const {return count==5 && uint32_t(now-lastSample)<=1500 && filtered>=threshold;}
  bool canRequest(uint32_t now) const {
    return !latched && strong && near(now) && uint32_t(now-strongSince)>=800 && (!attempted || uint32_t(now-lastAttempt)>=10000);
  }
  void attempt(uint32_t now){attempted=true;lastAttempt=now;}
  void accept(){latched=true;strong=weak=false;}
  bool isLatched() const{return latched;}
};
