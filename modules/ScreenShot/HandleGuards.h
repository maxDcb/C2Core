#ifndef HANDLE_GUARDS_H
#define HANDLE_GUARDS_H
#include "windows.h"
#include <string>

namespace guards
{
    class CHandleGuard
    {
        HANDLE h_;
        CHandleGuard(CHandleGuard&);
        CHandleGuard& operator=(CHandleGuard&);
    public:
        explicit CHandleGuard(HANDLE h=0)
            :h_(h){}
            ~CHandleGuard(void)
            {
                if(h_)CloseHandle(h_);
            }
            HANDLE get() const {return h_;}
            HANDLE release()
            {
                HANDLE tmp = h_;
                h_ = 0;
                return tmp;
            }
            void reset(HANDLE h)
            {
                if(h_)CloseHandle(h_);
                h_ = h;
            }
    };

    class CDCGuard
    {
        HDC h_;
        CDCGuard(const CDCGuard&);
        CDCGuard& operator=(CDCGuard&);
    public:
        explicit CDCGuard(HDC h)
            :h_(h){}
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
    };
    class CBitMapGuard
    {
        HBITMAP h_;
        CBitMapGuard(const CBitMapGuard&);
        CBitMapGuard& operator=(CBitMapGuard&);
    public:
        explicit CBitMapGuard(HBITMAP h)
            :h_(h){}
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
    };

 }//namespace utils
#endif