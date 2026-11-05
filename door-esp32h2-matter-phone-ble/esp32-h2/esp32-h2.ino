#include <Arduino.h>
#include <Matter.h>
#include <MatterEndpoints/MatterGenericSwitch.h>
#include <Preferences.h>
#include <platform/ESP32/BLEManagerImpl.h>
#include <platform/ConnectivityManager.h>
#include <platform/CHIPDeviceLayer.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <esp_system.h>
#include <bootloader_random.h>
#include <atomic>
#include <vector>
#include <platform/DeviceInfoProvider.h>
#include <app/server/Server.h>
#include <mbedtls/base64.h>
extern "C" {
#include <host/ble_hs.h>
#include <host/ble_gap.h>
#include <host/ble_gatt.h>
#include <host/ble_uuid.h>
#include <os/os_mbuf.h>
#include <services/gap/ble_svc_gap.h>
}
#include "config.h"
#include "ReaderSettings.h"
#include "PersistentDoorId.h"
#include "DoorLabelProvider.h"
#include "ProximityGate.h"
#if !CONFIG_IDF_TARGET_ESP32H2 || !CONFIG_BT_NIMBLE_ENABLED
#error Requires ESP32-H2 with Matter + NimBLE
#endif
#if CONFIG_USE_BLE_ONLY_FOR_COMMISSIONING
#error Matter must retain NimBLE after commissioning
#endif
uint32_t doorId=0;
constexpr size_t PERMIT_SIZE=150,AUTH_SIZE=286;
MatterGenericSwitch accessSwitch;
DoorLabelProvider doorLabelProvider;
char bleDeviceName[30]{};
uint8_t issuerPublic[65]{},doorPrivate[32]{},doorPublic[65]{};
bool issuerConfigured=false;
struct ConfigSnapshot { char payload[121]; size_t length; };
QueueHandle_t configEvents;
bool doorAdvertising=false;
std::atomic<bool> commissioningWindow{false};
std::atomic<bool> configReadPending{false};
std::atomic<bool> labelStorageReady{false};

ProximityGate gate;
uint8_t nonce[16],packet[AUTH_SIZE];size_t packetLength=0;
uint32_t challengeCreatedAt=0,lastRssiRequest=0,lastRssiLog=0;
bool challengeValid=false,receiving=false,linked=false,clientReady=false;
uint16_t connection=BLE_HS_CONN_HANDLE_NONE;
std::atomic<uint16_t> notifyConnection{BLE_HS_CONN_HANDLE_NONE};
std::atomic<bool> commissioned{false},threadAttached{false},queueOverflow{false};
struct Event{uint8_t kind;uint16_t connection;size_t size;uint8_t data[20];};
QueueHandle_t events;
void enqueue(const Event &event){if(xQueueSend(events,&event,0)!=pdTRUE)queueOverflow.store(true);}
bool matterReady(){return commissioned.load() && threadAttached.load();}

// Value storage is shared between Arduino loop and NimBLE host callbacks.
// Never initialize a second BLE host: Matter owns NimBLE.
class SharedValue {
  portMUX_TYPE mux=portMUX_INITIALIZER_UNLOCKED;
  uint8_t bytes[128]{};size_t length=0;
public:
  uint16_t handle=0;
  std::atomic<bool> subscribed{false};
  void setValue(const uint8_t *value,size_t n){portENTER_CRITICAL(&mux);length=std::min(n,sizeof(bytes));memcpy(bytes,value,length);portEXIT_CRITICAL(&mux);}
  void setValue(const char *text){setValue((const uint8_t*)text,strlen(text));}
  int read(os_mbuf *om){uint8_t copy[128];size_t n;portENTER_CRITICAL(&mux);n=length;memcpy(copy,bytes,n);portEXIT_CRITICAL(&mux);return os_mbuf_append(om,copy,n)==0?0:BLE_ATT_ERR_INSUFFICIENT_RES;}
  void notify(){
    uint16_t conn=notifyConnection.load();if(conn==BLE_HS_CONN_HANDLE_NONE || !handle || !subscribed.load())return;
    uint8_t copy[128];size_t n;portENTER_CRITICAL(&mux);n=length;memcpy(copy,bytes,n);portEXIT_CRITICAL(&mux);
    os_mbuf *om=ble_hs_mbuf_from_flat(copy,n);if(om)ble_gatts_notify_custom(conn,handle,om);
  }
};
SharedValue challengeValue,resultValue,telemetryValue;
SharedValue *challengeCharacteristic=&challengeValue,*resultCharacteristic=&resultValue,*telemetryCharacteristic=&telemetryValue;
int rng(void *, unsigned char *out, size_t count) { esp_fill_random(out, count); return 0; }
void hash(const uint8_t *data, size_t size, uint8_t out[32]) { mbedtls_sha256(data, size, out, 0); }
uint64_t read64(const uint8_t *p) { uint64_t v=0; for(int i=7;i>=0;--i) v=(v<<8)|p[i]; return v; }
uint32_t read32(const uint8_t *p) { return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24); }
void writeDoor(uint8_t *p) { encodeDoorId(doorId,p); }

bool verify(const uint8_t pub[65], const uint8_t *message, size_t length, const uint8_t signature[64]) {
  uint8_t digest[32];hash(message,length,digest);
  mbedtls_ecp_group group;mbedtls_ecp_point point;mbedtls_mpi r,s;
  mbedtls_ecp_group_init(&group);mbedtls_ecp_point_init(&point);mbedtls_mpi_init(&r);mbedtls_mpi_init(&s);
  int rc=mbedtls_ecp_group_load(&group,MBEDTLS_ECP_DP_SECP256R1);
  if(!rc)rc=mbedtls_ecp_point_read_binary(&group,&point,pub,65);
  if(!rc)rc=mbedtls_ecp_check_pubkey(&group,&point);
  if(!rc)rc=mbedtls_mpi_read_binary(&r,signature,32);
  if(!rc)rc=mbedtls_mpi_read_binary(&s,signature+32,32);
  if(!rc)rc=mbedtls_ecdsa_verify(&group,digest,32,&point,&r,&s);
  mbedtls_ecp_group_free(&group);mbedtls_ecp_point_free(&point);mbedtls_mpi_free(&r);mbedtls_mpi_free(&s);
  return rc==0;
}
bool signDoor(const uint8_t *message,size_t length,uint8_t signature[64]) {
  uint8_t digest[32];hash(message,length,digest);
  mbedtls_ecp_group group;mbedtls_mpi d,r,s;
  mbedtls_ecp_group_init(&group);mbedtls_mpi_init(&d);mbedtls_mpi_init(&r);mbedtls_mpi_init(&s);
  int rc=mbedtls_ecp_group_load(&group,MBEDTLS_ECP_DP_SECP256R1);
  if(!rc)rc=mbedtls_mpi_read_binary(&d,doorPrivate,32);
  if(!rc)rc=mbedtls_ecdsa_sign(&group,&r,&s,&d,digest,32,rng,nullptr);
  if(!rc)rc=mbedtls_mpi_write_binary(&r,signature,32);
  if(!rc)rc=mbedtls_mpi_write_binary(&s,signature+32,32);
  mbedtls_ecp_group_free(&group);mbedtls_mpi_free(&d);mbedtls_mpi_free(&r);mbedtls_mpi_free(&s);
  return rc==0;
}
void result(const char *value){
 resultCharacteristic->setValue(value);if(linked && clientReady)resultCharacteristic->notify();
 Serial.printf("[AUTH] %s\r\n",value);
}
void generateChallenge() {
  uint8_t frame[84], message[sizeof("DoorKey-door-v1")-1+20];
  esp_fill_random(nonce,16);writeDoor(frame);memcpy(frame+4,nonce,16);
  memcpy(message,"DoorKey-door-v1",sizeof("DoorKey-door-v1")-1);
  memcpy(message+sizeof("DoorKey-door-v1")-1,frame,20);
  challengeValid=signDoor(message,sizeof(message),frame+20);
  if(!challengeValid){challengeCharacteristic->setValue("");result("DENY:CRYPTO");return;}
  challengeCharacteristic->setValue(frame,sizeof(frame));
  challengeCreatedAt=millis();packetLength=0;receiving=false;result("READY");
  Serial.print("[BLE] Challenge semnat: ");for(uint8_t b:nonce)Serial.printf("%02x",b);Serial.print("\r\n");
}
void authenticate() {
  if(!gate.near(millis()) || gate.isLatched()){challengeValid=false;receiving=false;result("DENY:PROXIMITY");return;}
  // Every verification attempt consumes this session's nonce, even if invalid.
  bool fresh=challengeValid && millis()-challengeCreatedAt<30000;
  challengeValid=false;receiving=false;
  if(!fresh){result("DENY:STALE");return;}
  if(packetLength!=AUTH_SIZE){result("DENY:LENGTH");return;}
  if(!issuerConfigured){result("DENY:NO_ISSUER");return;}
  if(packet[0]!=1 || read32(packet+1)!=doorId){result("DENY:DOOR");return;}
  if(!verify(issuerPublic,packet,86,packet+86)){result("DENY:PERMIT");return;}
  uint8_t timeMessage[sizeof("DoorKey-time-v2")-1+60];
  const size_t td=sizeof("DoorKey-time-v2")-1;
  memcpy(timeMessage,"DoorKey-time-v2",td);writeDoor(timeMessage+td);
  memcpy(timeMessage+td+4,nonce,16);memcpy(timeMessage+td+20,packet+150,8);
  hash(packet,PERMIT_SIZE,timeMessage+td+28);
  if(!verify(issuerPublic,timeMessage,sizeof(timeMessage),packet+158)){result("DENY:TIME_PROOF");return;}
  uint64_t now=read64(packet+150),start=read64(packet+5),end=read64(packet+13);
  if(end<=start || now<start || now>=end){result("DENY:EXPIRED");return;}
  uint8_t message[sizeof("DoorKey-auth-v1")-1+52];
  const size_t ad=sizeof("DoorKey-auth-v1")-1;
  memcpy(message,"DoorKey-auth-v1",ad);writeDoor(message+ad);memcpy(message+ad+4,nonce,16);
  hash(packet,222,message+ad+20);
  if(!verify(packet+21,message,sizeof(message),packet+222)){result("DENY:PHONE");return;}
  if(!matterReady()){result("DENY:MATTER_OFFLINE");return;}
  gate.accept();
  accessSwitch.click();
  Serial.print("[MATTER] InitialPress access event scheduled (delivery not acknowledged)\r\n");
  char accepted[24];snprintf(accepted,sizeof(accepted),"ACCEPT:%u",doorId);result(accepted);
  Serial.printf("[ACCESS] Telefon autorizat pentru %s (ID=%u). Eveniment local disponibil.\r\n",bleDeviceName,doorId);
  // Integrate the already-existing actuation here, when requested. No GPIO changes.
}

void processDoorCommand(const uint8_t *v,size_t n){
  if(!n)return;
  if(v[0]==5 && n==1){clientReady=true;challengeValid=false;receiving=false;packetLength=0;result(gate.isLatched()?"LATCHED":"WAIT:PROXIMITY");return;}
  if(!clientReady){result("DENY:LISTEN");return;}
  if(v[0]==4 && n==1){challengeValid=false;receiving=false;packetLength=0;result("WAIT:RETRY");return;}
  if(!challengeValid || millis()-challengeCreatedAt>=30000){result("DENY:STALE");return;}
  if(v[0]==1 && n==1){packetLength=0;receiving=true;return;}
  if(v[0]==2 && receiving && n>1){
    if(packetLength+n-1>AUTH_SIZE){receiving=false;challengeValid=false;result("DENY:OVERFLOW");return;}
    memcpy(packet+packetLength,v+1,n-1);packetLength+=n-1;return;
  }
  if(v[0]==3 && n==1 && receiving){authenticate();return;}
  receiving=false;challengeValid=false;result("DENY:COMMAND");
}
static const ble_uuid128_t uuid1=BLE_UUID128_INIT(0x00,0x12,0x6c,0x50,0x1f,0x78,0xd0,0x9a,0x9d,0x4b,0x3a,0x6e,0x01,0x10,0x96,0x84);
static const ble_uuid128_t uuid2=BLE_UUID128_INIT(0x00,0x12,0x6c,0x50,0x1f,0x78,0xd0,0x9a,0x9d,0x4b,0x3a,0x6e,0x02,0x10,0x96,0x84);
static const ble_uuid128_t uuid3=BLE_UUID128_INIT(0x00,0x12,0x6c,0x50,0x1f,0x78,0xd0,0x9a,0x9d,0x4b,0x3a,0x6e,0x03,0x10,0x96,0x84);
static const ble_uuid128_t uuid4=BLE_UUID128_INIT(0x00,0x12,0x6c,0x50,0x1f,0x78,0xd0,0x9a,0x9d,0x4b,0x3a,0x6e,0x04,0x10,0x96,0x84);
static const ble_uuid128_t uuid5=BLE_UUID128_INIT(0x00,0x12,0x6c,0x50,0x1f,0x78,0xd0,0x9a,0x9d,0x4b,0x3a,0x6e,0x05,0x10,0x96,0x84);
static ble_gatt_chr_def characteristics[5]{};
static ble_gatt_svc_def service{};
int gattAccess(uint16_t conn,uint16_t attr,ble_gatt_access_ctxt *ctx,void *arg){
  if(ctx->op==BLE_GATT_ACCESS_OP_READ_CHR){
    if(attr==challengeValue.handle)return challengeValue.read(ctx->om);
    if(attr==resultValue.handle)return resultValue.read(ctx->om);
    if(attr==telemetryValue.handle)return telemetryValue.read(ctx->om);
    return BLE_ATT_ERR_READ_NOT_PERMITTED;
  }
  if(ctx->op!=BLE_GATT_ACCESS_OP_WRITE_CHR || arg!=(void*)1)return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
  if(!matterReady())return BLE_ATT_ERR_UNLIKELY;
  Event e{};e.kind=3;e.connection=conn;e.size=OS_MBUF_PKTLEN(ctx->om);
  if(!e.size || e.size>sizeof(e.data))return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
  if(os_mbuf_copydata(ctx->om,0,e.size,e.data)!=0)return BLE_ATT_ERR_UNLIKELY;
  if(xQueueSend(events,&e,0)!=pdTRUE)return BLE_ATT_ERR_INSUFFICIENT_RES;
  return 0;
}
int gapEvent(ble_gap_event *event,void*){
  Event e{};
  if(event->type==BLE_GAP_EVENT_SUBSCRIBE){
    if(event->subscribe.attr_handle==resultValue.handle)resultValue.subscribed.store(event->subscribe.cur_notify);
    if(event->subscribe.attr_handle==telemetryValue.handle)telemetryValue.subscribed.store(event->subscribe.cur_notify);
  }
  if(event->type==BLE_GAP_EVENT_CONNECT){doorAdvertising=false;if(event->connect.status==0){resultValue.subscribed.store(false);telemetryValue.subscribed.store(false);e.kind=1;e.connection=event->connect.conn_handle;enqueue(e);}}
  if(event->type==BLE_GAP_EVENT_DISCONNECT){resultValue.subscribed.store(false);telemetryValue.subscribed.store(false);e.kind=2;e.connection=event->disconnect.conn.conn_handle;enqueue(e);}
  return 0;
}
void configureDoorGatt(){
  characteristics[0].uuid=&uuid2.u;characteristics[0].access_cb=gattAccess;characteristics[0].flags=BLE_GATT_CHR_F_READ;characteristics[0].val_handle=&challengeValue.handle;
  characteristics[1].uuid=&uuid3.u;characteristics[1].access_cb=gattAccess;characteristics[1].flags=BLE_GATT_CHR_F_WRITE;characteristics[1].arg=(void*)1;
  characteristics[2].uuid=&uuid4.u;characteristics[2].access_cb=gattAccess;characteristics[2].flags=BLE_GATT_CHR_F_READ|BLE_GATT_CHR_F_NOTIFY;characteristics[2].val_handle=&resultValue.handle;
  characteristics[3].uuid=&uuid5.u;characteristics[3].access_cb=gattAccess;characteristics[3].flags=BLE_GATT_CHR_F_READ|BLE_GATT_CHR_F_NOTIFY;characteristics[3].val_handle=&telemetryValue.handle;
  service.type=BLE_GATT_SVC_TYPE_PRIMARY;service.uuid=&uuid1.u;service.characteristics=characteristics;
  // Extra-service vector excludes the sentinel: CHIP adds its service + terminator.
  std::vector<ble_gatt_svc_def> extra{service};
  CHIP_ERROR rc=chip::DeviceLayer::Internal::BLEMgrImpl().ConfigureExtraServices(extra,true);
  if(rc!=CHIP_NO_ERROR){Serial.printf("[FATAL] GATT config: %ld\r\n",long(rc.AsInteger()));while(true)delay(1000);}
}
void startDoorAdvertising(){
  if(!challengeValue.handle || !resultValue.handle || !matterReady() || !ble_hs_synced() || linked || ble_gap_adv_active())return;
  ble_svc_gap_device_name_set(bleDeviceName);
  uint8_t ownType;if(ble_hs_id_infer_auto(0,&ownType)!=0)return;
  ble_hs_adv_fields fields{};fields.flags=BLE_HS_ADV_F_DISC_GEN|BLE_HS_ADV_F_BREDR_UNSUP;
  fields.uuids128=const_cast<ble_uuid128_t*>(&uuid1);fields.num_uuids128=1;fields.uuids128_is_complete=1;
  int rc=ble_gap_adv_set_fields(&fields);if(rc)return;
  ble_hs_adv_fields response{};response.name=(uint8_t*)bleDeviceName;response.name_len=strlen(bleDeviceName);response.name_is_complete=1;
  if(ble_gap_adv_rsp_set_fields(&response)!=0)return;
  ble_gap_adv_params params{};params.conn_mode=BLE_GAP_CONN_MODE_UND;params.disc_mode=BLE_GAP_DISC_MODE_GEN;
  params.itvl_min=160;params.itvl_max=240;
  rc=ble_gap_adv_start(ownType,nullptr,BLE_HS_FOREVER,&params,gapEvent,nullptr);
  if(!rc){doorAdvertising=true;Serial.printf("[BLE] %s advertising on Matter's NimBLE host\r\n",bleDeviceName);}
  else Serial.printf("[BLE] Advertising retry, rc=%d\r\n",rc);
}
void printPairing(){
  Serial.printf("[PAIR] Manual code: %s\r\n",Matter.getManualPairingCode().c_str());
  Serial.printf("[PAIR] QR URL: %s\r\n",Matter.getOnboardingQRCodeUrl().c_str());
}
bool validPublicKey(const uint8_t pub[65]) {
 mbedtls_ecp_group g;mbedtls_ecp_point p;mbedtls_ecp_group_init(&g);mbedtls_ecp_point_init(&p);
 int rc=mbedtls_ecp_group_load(&g,MBEDTLS_ECP_DP_SECP256R1);
 if(!rc)rc=mbedtls_ecp_point_read_binary(&g,&p,pub,65);
 if(!rc)rc=mbedtls_ecp_check_pubkey(&g,&p);
 mbedtls_ecp_point_free(&p);mbedtls_ecp_group_free(&g);return rc==0;
}
void printIdentity(){
 Serial.printf("[IDENTITY] Door ID=%u BLE=%s Protocol=2\r\n",doorId,bleDeviceName);
 Serial.print("[IDENTITY] ESP32 public key: ");for(uint8_t b:doorPublic)Serial.printf("%02x",b);Serial.print("\r\n");
 Serial.print("[IDENTITY] Manager SHA256: ");uint8_t digest[32];hash(issuerPublic,65,digest);
 if(issuerConfigured){for(uint8_t b:digest)Serial.printf("%02x",b);}else Serial.print("UNCONFIGURED");Serial.print("\r\n");
}
bool loadIdentity(){
 Preferences p;if(!p.begin("doorkey-device",false))return false;
 if(p.isKey("private")&&p.getBytesLength("private")!=32){p.end();return false;}
 bool saved=p.getBytesLength("private")==32;
 if(saved)p.getBytes("private",doorPrivate,32);
 mbedtls_ecp_group g;mbedtls_ecp_point q;mbedtls_mpi d;mbedtls_ecp_group_init(&g);mbedtls_ecp_point_init(&q);mbedtls_mpi_init(&d);
 int rc=mbedtls_ecp_group_load(&g,MBEDTLS_ECP_DP_SECP256R1);
 if(!saved){
  if(!rc)rc=mbedtls_ecp_gen_privkey(&g,&d,rng,nullptr);
  if(!rc)rc=mbedtls_mpi_write_binary(&d,doorPrivate,32);
 }
 if(!rc)rc=mbedtls_mpi_read_binary(&d,doorPrivate,32);
 if(!rc)rc=mbedtls_ecp_check_privkey(&g,&d);
 if(!rc)rc=mbedtls_ecp_mul(&g,&q,&d,&g.G,rng,nullptr);
 size_t length=0;if(!rc)rc=mbedtls_ecp_point_write_binary(&g,&q,MBEDTLS_ECP_PF_UNCOMPRESSED,&length,doorPublic,65);
 if(!rc&&!saved&&p.putBytes("private",doorPrivate,32)!=32)rc=-1;
 if(!rc&&!loadPersistentDoorId(p,[](){return esp_random();},doorId))rc=-1;
 if(!rc){
  String initialName=p.getString("initial_name","");
  if(!ReaderSettings::validName(initialName.c_str(),initialName.length())){
   uint8_t digest[32];hash(doorPublic,65,digest);
   char generated[16];snprintf(generated,sizeof(generated),"Door-%02X%02X",digest[0],digest[1]);initialName=generated;
   if(p.putString("initial_name",initialName)!=initialName.length())rc=-1;
  }
  if(!rc)strlcpy(bleDeviceName,initialName.c_str(),sizeof(bleDeviceName));
 }
 p.end();mbedtls_mpi_free(&d);mbedtls_ecp_point_free(&q);mbedtls_ecp_group_free(&g);return rc==0;
}
void readMatterConfig(){
 chip::DeviceLayer::SystemLayer().ScheduleLambda([](){
  auto* provider=chip::DeviceLayer::GetDeviceInfoProvider();
  auto* it=provider?provider->IterateUserLabel(accessSwitch.getEndPointId()):nullptr;
  if(it){
   char parts[4][31]{};size_t lengths[4]{};unsigned mask=0;bool valid=true;
   chip::DeviceLayer::DeviceInfoProvider::UserLabelType item;
   while(it->Next(item)){
    auto label=item.label;auto value=item.value;
    if(label.size()<2||label.size()>16||value.size()>16||label.data()[0]!='D'||label.data()[1]<'0'||label.data()[1]>'3'){valid=false;break;}
    unsigned index=label.data()[1]-'0';if(mask&(1u<<index)){valid=false;break;}mask|=1u<<index;
    lengths[index]=label.size()-2+value.size();memcpy(parts[index],label.data()+2,label.size()-2);memcpy(parts[index]+label.size()-2,value.data(),value.size());
   }
   it->Release();
   if(valid&&mask==15){ConfigSnapshot snapshot{};for(unsigned i=0;i<4;i++){memcpy(snapshot.payload+snapshot.length,parts[i],lengths[i]);snapshot.length+=lengths[i];}xQueueOverwrite(configEvents,&snapshot);}
  }
  configReadPending.store(false);
 });
}
void applyConfig(const char* payload,size_t length,bool persist){
 char name[30];uint8_t key[65];
 if(!ReaderSettings::decode(payload,length,name,key)||!validPublicKey(key))return;
 if(issuerConfigured&&!strcmp(name,bleDeviceName)&&!memcmp(key,issuerPublic,65))return;
 if(persist){Preferences p;if(!p.begin("doorkey-config",false))return;size_t written=p.putBytes("settings",payload,length);p.end();if(written!=length){Serial.print("[CONFIG] NVS write failed\r\n");return;}}
 // Any trust or name change cancels the in-flight authorization and disconnects the phone.
 challengeValid=false;receiving=false;packetLength=0;clientReady=false;
 memcpy(bleDeviceName,name,strlen(name)+1);memcpy(issuerPublic,key,65);issuerConfigured=true;
 if(linked)ble_gap_terminate(connection,BLE_ERR_REM_USER_CONN_TERM);
 if(doorAdvertising&&!commissioningWindow.load()){ble_gap_adv_stop();doorAdvertising=false;}
 if(ble_hs_synced())ble_svc_gap_device_name_set(bleDeviceName);
 Serial.printf("[CONFIG] Saved BLE name=%s and Manager public key\r\n",bleDeviceName);printIdentity();
}
void setup(){
  Serial.begin(115200);delay(1500);events=xQueueCreate(32,sizeof(Event));
  configEvents=xQueueCreate(1,sizeof(ConfigSnapshot));
  if(!events||!configEvents){while(true)delay(1000);}
  bootloader_random_enable();
  if(!loadIdentity()){Serial.print("[FATAL] Device identity storage/crypto failure\r\n");while(true)delay(1000);}
  bootloader_random_disable();
  Preferences configPrefs;if(configPrefs.begin("doorkey-config",true)){
   ConfigSnapshot saved{};saved.length=configPrefs.getBytesLength("settings");
   if(saved.length&&saved.length<=120){configPrefs.getBytes("settings",saved.payload,saved.length);applyConfig(saved.payload,saved.length,false);}configPrefs.end();
  }
  printIdentity();
  gate.threshold=PROXIMITY_THRESHOLD;
  Serial.printf("\r\n[BOOT] DoorKey H2 Matter/Thread + BLE | flash=%u\r\n",ESP.getFlashChipSize());
  if(ESP.getFlashChipSize()<4*1024*1024){Serial.print("[FATAL] This build needs 4 MB flash\r\n");while(true)delay(1000);}
  Matter.selectNetwork(MATTER_NETWORK_THREAD);
  Matter.setBLEMemoryReleaseEnabled(false);
  Matter.setVendorName("DoorKey Prototype");Matter.setProductName("BLE Access Button");Matter.setDeviceName(bleDeviceName);
  bootloader_random_enable();
  Preferences prefs;prefs.begin("doorkey-setup",false);
  uint32_t passcode=prefs.getUInt("pin",0);
  if(!passcode || !Matter.setSetupPasscode(passcode)){
    do{passcode=10000000u+esp_random()%89999999u;}while(!Matter.setSetupPasscode(passcode));
    prefs.putUInt("pin",passcode);
  }
  uint16_t discriminator=prefs.getUShort("disc",0xffff);
  if(discriminator>4095){discriminator=esp_random()%4096;prefs.putUShort("disc",discriminator);}
  Matter.setSetupDiscriminator(discriminator);prefs.end();bootloader_random_disable();
  // All services must be configured before Matter initializes the NimBLE host.
  configureDoorGatt();
  if(!accessSwitch.begin(MatterGenericSwitch::FEATURE_SIMPLE)){
    Serial.print("[FATAL] Matter switch endpoint\r\n");while(true)delay(1000);
  }
  Matter.onEvent([](matterEvent_t type,const chip::DeviceLayer::ChipDeviceEvent*){
    if(type==MATTER_COMMISSIONING_WINDOW_OPEN)commissioningWindow.store(true);
    if(type==MATTER_COMMISSIONING_WINDOW_CLOSED)commissioningWindow.store(false);
    commissioned.store(Matter.isDeviceCommissioned());threadAttached.store(Matter.isThreadConnected());
    Serial.printf("[MATTER] event=%u\r\n",unsigned(type));
  });
  Matter.begin();
  // The Arduino prebuilt SDK selects CONFIG_NONE_DEVICE_INFO_PROVIDER. The
  // UserLabel cluster exists, but all writes fail until its provider/storage are bound.
  chip::DeviceLayer::SystemLayer().ScheduleLambda([](){
    auto* provider=chip::DeviceLayer::GetDeviceInfoProvider();
    if(!provider)provider=&doorLabelProvider;
    provider->SetStorageDelegate(&chip::Server::GetInstance().GetPersistentStorage());
    chip::DeviceLayer::SetDeviceInfoProvider(provider);
    labelStorageReady.store(true);
    Serial.print("[CONFIG] Matter UserLabel persistence ready\r\n");
  });
  result("IDLE");printPairing();
  Serial.print("[INFO] Pair Matter first. Door BLE starts after Thread attachment. Commands: PAIR / STATUS / IDENTITY / THRESH -30 / FACTORY RESET\r\n");
}
void loop(){
  static uint32_t lastState=0;
  if(millis()-lastState>=2000){
    lastState=millis();
    chip::DeviceLayer::SystemLayer().ScheduleLambda([](){
      commissioned.store(Matter.isDeviceCommissioned());threadAttached.store(Matter.isThreadConnected());
    });
  }
  bool c=commissioned.load(),t=threadAttached.load();
  static bool oldC=false,oldT=false;
  if(c!=oldC || t!=oldT){oldC=c;oldT=t;Serial.printf("[MATTER] commissioned=%d thread=%d\r\n",c,t);}
  ConfigSnapshot configUpdate{};if(xQueueReceive(configEvents,&configUpdate,0)==pdTRUE)applyConfig(configUpdate.payload,configUpdate.length,true);
  static uint32_t lastConfigRead=0;
  if(c&&labelStorageReady.load()&&millis()-lastConfigRead>=1000&&!configReadPending.exchange(true)){lastConfigRead=millis();readMatterConfig();}
  Event e;
  while(xQueueReceive(events,&e,0)==pdTRUE){
    if(e.kind==1){
      if(linked){ble_gap_terminate(e.connection,BLE_ERR_REM_USER_CONN_TERM);continue;}
      linked=true;connection=e.connection;notifyConnection.store(connection);clientReady=false;
      gate.resetSamples();challengeValid=false;receiving=false;packetLength=0;
      Serial.print("[BLE] Phone connected to Door GATT\r\n");
    }else if(e.kind==2 && e.connection==connection){
      linked=false;clientReady=false;connection=BLE_HS_CONN_HANDLE_NONE;notifyConnection.store(connection);
      gate.resetSamples();challengeValid=false;receiving=false;packetLength=0;challengeValue.setValue("");result("DISCONNECTED");
    }else if(e.kind==3 && linked && e.connection==connection){processDoorCommand(e.data,e.size);}
  }
  if(queueOverflow.exchange(false)){challengeValid=false;receiving=false;clientReady=false;result("DENY:QUEUE");if(linked)ble_gap_terminate(connection,BLE_ERR_REM_USER_CONN_TERM);}
  uint32_t now=millis();
  if(linked && now-lastRssiRequest>=250){
    lastRssiRequest=now;int8_t rssi;
    if(ble_gap_conn_rssi(connection,&rssi)==0){
      bool latched=gate.isLatched();
      if(gate.sample(rssi,now) && now-lastRssiLog>=1000){
        lastRssiLog=now;char text[20];snprintf(text,sizeof(text),"%d,%d,%d",rssi,gate.filtered,gate.threshold);
        telemetryValue.setValue(text);telemetryValue.notify();
        Serial.printf("[RSSI] raw=%d median=%d prag=%d %s\r\n",rssi,gate.filtered,gate.threshold,gate.isLatched()?"LATCHED":"ARMED");
      }
      if(latched && !gate.isLatched())result("REARMED");
    }
  }
  if(!matterReady() && challengeValid){challengeValid=false;receiving=false;result("DENY:MATTER_OFFLINE");}
  if(challengeValid && now-challengeCreatedAt>=30000){challengeValid=false;receiving=false;result("DENY:TIMEOUT");}
  if(matterReady() && linked && clientReady && !challengeValid && !receiving && gate.canRequest(now)){gate.attempt(now);generateChallenge();}
  static uint32_t lastAdv=0;if(now-lastAdv>=2000){lastAdv=now;startDoorAdvertising();}
  static String line;
  while(Serial.available()){
    char ch=Serial.read();
    if(ch=='\n'||ch=='\r'){
      if(line=="PAIR")printPairing();
      else if(line=="IDENTITY")printIdentity();
      else if(line=="STATUS"){printIdentity();Serial.printf("[STATUS] Matter=%d Thread=%d BLE=%d heap=%u\r\n",c,t,linked,ESP.getFreeHeap());}
      else if(line=="FACTORY RESET"){Serial.print("[RESET] Removing Matter/Thread enrollment\r\n");Matter.decommission();}
      else if(line.startsWith("THRESH ")){
        int v=line.substring(7).toInt();
        if(v>=-85 && v<=-20){
          gate.threshold=v;gate.resetSamples();challengeValid=false;receiving=false;
          Serial.printf("[CONFIG] Threshold=%d\r\n",v);
        }else Serial.print("[CONFIG] Invalid threshold; use -85 through -20 dBm\r\n");
      }
      line="";
    }else if(line.length()<40)line+=ch;
  }
  delay(10);
}
