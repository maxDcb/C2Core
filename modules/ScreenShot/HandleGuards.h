#pragma once

#include "windows.h"
#include <string>


namespace guards
{
    

class CDCGuard
{
public:
    explicit CDCGuard(HDC h)
    :h_(h)
    {

    }

    ~CDCGuard(void)
    {
        if(h_)DeleteDC(h_);
    }

    void reset(HDC h)
    {
        if(h_ == h)
            return;
        if(h_)DeleteDC(h_);
        h_ = h;
    }

    void release()
    {
        h_ = 0;
    }

    HDC get()
    {
        return h_;
    }

private:
    HDC h_;
    CDCGuard(const CDCGuard&);
    CDCGuard& operator=(CDCGuard&);

};


class CBitMapGuard
{
public:
    explicit CBitMapGuard(HBITMAP h)
    :h_(h)
    {

    }

    ~CBitMapGuard(void)
    {
        if(h_)DeleteObject(h_);
    }

    void reset(HBITMAP h)
    {
        if(h_ == h)
            return;
        if(h_)DeleteObject(h_);
        h_ = h;
    }

    HBITMAP get()
    {
        return h_;
    }

private:
    HBITMAP h_;
    CBitMapGuard(const CBitMapGuard&);
    CBitMapGuard& operator=(CBitMapGuard&);

};


}
