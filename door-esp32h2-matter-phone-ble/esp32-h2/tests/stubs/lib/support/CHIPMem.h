#pragma once
#include <new>
#include <utility>
namespace chip {namespace Platform {
template<class T,class...Args>T*New(Args&&...args){return new(std::nothrow)T(std::forward<Args>(args)...);}
template<class T>void Delete(T*p){delete p;}
}}
