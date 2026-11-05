#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
// Standard Matter UserLabel supports four 16-byte label/value pairs. Encode one
// complete configuration in those pairs so stock Matter Server needs no vendor extension.
namespace ReaderSettings {
constexpr size_t MAX_NAME=29,KEY_BYTES=65,PAYLOAD_MAX=120;
inline bool validName(const char* name,size_t n){if(!n||n>MAX_NAME)return false;for(size_t i=0;i<n;i++)if(name[i]<32||name[i]>126)return false;return true;}
inline int digit(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;}
inline int b64(char c){const char* chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";const char* p=strchr(chars,c);return p&&c?int(p-chars):-1;}
inline bool decode(const char* payload,size_t n,char name[30],uint8_t key[65]){
 if(n<3||payload[0]!='1')return false;
 int h=digit(payload[1]),l=digit(payload[2]);if(h<0||l<0)return false;size_t len=h*16+l;
 if(n!=3+len+88||!validName(payload+3,len))return false;
 const char* encoded=payload+3+len;if(encoded[87]!='=')return false;
 size_t out=0;
 for(size_t i=0;i<88;i+=4){
  int a=b64(encoded[i]),b=b64(encoded[i+1]),c=b64(encoded[i+2]),d=i==84?0:b64(encoded[i+3]);
  if(a<0||b<0||c<0||d<0)return false;
  if(out<65)key[out++]=(a<<2)|(b>>4);
  if(out<65)key[out++]=(b<<4)|(c>>2);
  if(out<65)key[out++]=(c<<6)|d;
  if(i==84&&(c&3))return false;
 }
 if(key[0]!=4)return false;
 memcpy(name,payload+3,len);name[len]=0;return out==65;
}
}
