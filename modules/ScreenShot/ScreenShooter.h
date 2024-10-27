#ifndef _C_SCREEN_SHOOTER_H_
#define _C_SCREEN_SHOOTER_H_

#include <vector>
#include "HandleGuards.h"

namespace ScreenShooter
{
    void CaptureScreen(std::vector<unsigned char>& dataScreen);
    BOOL CALLBACK MonitorEnumProc(
        HMONITOR hMonitor,  // handle to display monitor
        HDC hdcMonitor,     // handle to monitor DC
        LPRECT lprcMonitor, // monitor intersection rectangle
        LPARAM dwData       // data
        );

    typedef std::vector<std::pair<HDC, RECT>> HDCPoolType;

    class CDisplayHandlesPool
    {
    private:
        HDCPoolType m_hdcPool;

        CDisplayHandlesPool(const CDisplayHandlesPool & other);
        CDisplayHandlesPool & operator = (CDisplayHandlesPool);
    public:

        typedef HDCPoolType::iterator iterator;

        CDisplayHandlesPool()
        {
            guards::CDCGuard captureGuard(0);
            HDC hDesktopDC = GetDC(NULL);
            if (!hDesktopDC)
            {
                // throw std::runtime_error("CDisplayHandlesPool: GetDC failed");
            }
            guards::CDCGuard desktopGuard(hDesktopDC);

            if(!EnumDisplayMonitors(hDesktopDC, NULL, MonitorEnumProc, reinterpret_cast<LPARAM>(this)))
            {
                // throw std::runtime_error("CDisplayHandlesPool: EnumDisplayMonitors failed");
            }
        }
        ~CDisplayHandlesPool()
        {
            for(HDCPoolType::iterator it = m_hdcPool.begin(); it != m_hdcPool.end(); ++it)
            {
                if(it->first)
                    DeleteDC(it->first);
            }
        }

        void AddHdcToPool(guards::CDCGuard & hdcGuard, RECT rect)
        {
            m_hdcPool.push_back(std::make_pair(hdcGuard.get(), rect));
            hdcGuard.release();
        }

        iterator begin()
        {
            return m_hdcPool.begin();
        }
        iterator end()
        {
            return m_hdcPool.end();
        }         
    };
}
#endif //_C_SCREEN_SHOOTER_H_