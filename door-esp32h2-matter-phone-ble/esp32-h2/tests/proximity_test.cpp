#include <cassert>
#include <cstdio>
#include "ProximityGate.h"
int main(){
 ProximityGate gate;
 for(unsigned t=0;t<3000;t+=250){gate.sample(-70,t);assert(!gate.canRequest(t));}
 // A single strong spike must not trigger.
 gate.sample(-35,3000);assert(!gate.canRequest(3000));
 gate.sample(-70,3250);assert(!gate.canRequest(3250));
 for(unsigned t=3500;t<=6000;t+=250)gate.sample(-45,t);
 assert(gate.canRequest(6000));gate.attempt(6000);gate.accept();
 for(unsigned t=6250;t<=20000;t+=250){gate.sample(-45,t);assert(!gate.canRequest(t));}
 // Reconnect/sample reset must not clear the successful-opening latch.
 gate.resetSamples();for(unsigned t=20250;t<=23000;t+=250)gate.sample(-45,t);
 assert(gate.isLatched());assert(!gate.canRequest(23000));
 // Stable weak readings rearm, then a fresh stable approach can request.
 for(unsigned t=23250;t<=26000;t+=250)gate.sample(-75,t);
 assert(!gate.isLatched());assert(!gate.canRequest(26000));
 for(unsigned t=26250;t<=29000;t+=250)gate.sample(-45,t);
 assert(gate.canRequest(29000));gate.attempt(29000);
 assert(!gate.canRequest(30000));
 for(unsigned t=29250;t<=39000;t+=250)gate.sample(-45,t);
 assert(gate.canRequest(39000));assert(!gate.near(41000));
 // A gap resets the median window; invalid/missing RSSI cannot qualify.
 assert(!gate.sample(127,41000));gate.sample(-40,42000);assert(!gate.canRequest(42000));
 // Unsigned time arithmetic remains safe across millis wrap.
 ProximityGate wrap;for(unsigned i=0;i<12;i++)wrap.sample(-45,0xfffff800u+i*250u);
 assert(wrap.canRequest(0xfffff800u+2750u));
 puts("PASS: proximity median, spike rejection, stable approach, latch, reconnect, departure rearm, cooldown, stale RSSI, gaps, millis wrap");
}
