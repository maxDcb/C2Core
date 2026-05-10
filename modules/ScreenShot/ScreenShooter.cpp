#ifdef _WIN32

#include "ScreenShooter.h"

#include <gdiplus.h>
#include <objidl.h>

#include <cwchar>
#include <iostream>
#include <vector>

using namespace guards;


bool CreatePngFinal(std::vector<unsigned char> & data, CDCGuard &captureGuard, CBitMapGuard & bmpGuard, HGDIOBJ & originalBmp);
void CaptureDesktop(CDCGuard &desktopGuard, CDCGuard &captureGuard, CBitMapGuard & bmpGuard, HGDIOBJ & originalBmp, int * width, int * height, int left, int top);
void SpliceImages(ScreenShooter::CDisplayHandlesPool * pHdcPool, CDCGuard &captureGuard, CBitMapGuard & bmpGuard, HGDIOBJ & originalBmp, int * width, int * height);


int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
    UINT num = 0;
    UINT size = 0;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0)
        return -1;

    std::vector<BYTE> buffer(size);
    auto imageCodecInfo = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buffer.data());
    if (Gdiplus::GetImageEncoders(num, size, imageCodecInfo) != Gdiplus::Ok)
        return -1;

    for (UINT index = 0; index < num; ++index)
    {
        if (std::wcscmp(imageCodecInfo[index].MimeType, format) == 0)
        {
            *pClsid = imageCodecInfo[index].Clsid;
            return static_cast<int>(index);
        }
    }
    return -1;
}


BOOL CALLBACK ScreenShooter::MonitorEnumProc(
  HMONITOR hMonitor,  // handle to display monitor
  HDC hdcMonitor,        // handle to monitor DC
  LPRECT lprcMonitor,   // monitor intersection rectangle
  LPARAM dwData         // data
)
{
    CBitMapGuard bmpGuard(0);
    HGDIOBJ originalBmp = NULL;
    int height = 0;
    int width = 0;
    CDCGuard desktopGuard(hdcMonitor);
    CDCGuard captureGuard(0);
    CaptureDesktop(desktopGuard, captureGuard, bmpGuard, originalBmp, &width, &height, lprcMonitor->left, lprcMonitor->top);

    RECT rect = *lprcMonitor;
    ScreenShooter::CDisplayHandlesPool * hdcPool = reinterpret_cast<ScreenShooter::CDisplayHandlesPool *>(dwData);
    hdcPool->AddHdcToPool(captureGuard, rect);
    return true;
}


void ScreenShooter::CaptureScreen(std::vector<unsigned char>& dataScreen)
{
    CDCGuard captureGuard(0);
    CBitMapGuard bmpGuard(0);
    HGDIOBJ originalBmp = NULL;
    int height = 0;
    int width = 0;

    ScreenShooter::CDisplayHandlesPool displayHandles;
    
    SpliceImages(& displayHandles, captureGuard, bmpGuard, originalBmp, &width, &height);

    CreatePngFinal(dataScreen, captureGuard, bmpGuard, originalBmp);
}


bool CreatePngFinal(std::vector<unsigned char> & data, CDCGuard &captureGuard, CBitMapGuard & bmpGuard, HGDIOBJ & originalBmp)
{
    data.clear();
    if (!bmpGuard.get())
        return false;

    if (originalBmp)
        SelectObject(captureGuard.get(), originalBmp);

    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken = 0;
    if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL) != Gdiplus::Ok)
        return false;

    CLSID pngClsid;
    bool success = false;
    IStream* stream = NULL;
    if (GetEncoderClsid(L"image/png", &pngClsid) >= 0
        && CreateStreamOnHGlobal(NULL, TRUE, &stream) == S_OK)
    {
        Gdiplus::Bitmap bitmap(bmpGuard.get(), NULL);
        if (bitmap.GetLastStatus() == Gdiplus::Ok
            && bitmap.Save(stream, &pngClsid, NULL) == Gdiplus::Ok)
        {
            HGLOBAL global = NULL;
            if (GetHGlobalFromStream(stream, &global) == S_OK)
            {
                STATSTG stat = {};
                void* memory = GlobalLock(global);
                if (memory != NULL
                    && stream->Stat(&stat, STATFLAG_NONAME) == S_OK
                    && stat.cbSize.QuadPart > 0)
                {
                    const SIZE_T size = static_cast<SIZE_T>(stat.cbSize.QuadPart);
                    auto begin = static_cast<unsigned char*>(memory);
                    data.assign(begin, begin + size);
                    success = true;
                }
                if (memory != NULL)
                    GlobalUnlock(global);
            }
        }
    }

    if (stream != NULL)
        stream->Release();
    Gdiplus::GdiplusShutdown(gdiplusToken);
    return success;
}


void CaptureDesktop(CDCGuard &desktopGuard, CDCGuard &captureGuard, CBitMapGuard & bmpGuard, HGDIOBJ & originalBmp, int * width, int * height, int left, int top)
{
    unsigned int nScreenWidth=GetDeviceCaps(desktopGuard.get(),HORZRES);
    unsigned int nScreenHeight=GetDeviceCaps(desktopGuard.get(),VERTRES);
    *height = nScreenHeight;
    *width = nScreenWidth;
   
    // Creating a memory device context (DC) compatible with the specified device
    HDC hCaptureDC = CreateCompatibleDC(desktopGuard.get());
    if (!hCaptureDC)
    {
        // throw std::runtime_error("CaptureDesktop: CreateCompatibleDC failed");
    }
    captureGuard.reset(hCaptureDC);

    // Creating a bitmap compatible with the device that is associated with the specified DC
    HBITMAP hCaptureBmp = CreateCompatibleBitmap(desktopGuard.get(), nScreenWidth, nScreenHeight);
    if(!hCaptureBmp)
    {
        // throw std::runtime_error("CaptureDesktop: CreateCompatibleBitmap failed");
    }
    bmpGuard.reset(hCaptureBmp);

    // Selecting an object into the specified DC 
    originalBmp = SelectObject(hCaptureDC, hCaptureBmp); 
    if (!originalBmp || (originalBmp == (HBITMAP)HGDI_ERROR))
    {
        // throw std::runtime_error("CaptureDesktop: SelectObject failed");
    }

    // Blitting the contents of the Desktop DC into the created compatible DC
    if (!BitBlt(hCaptureDC, 0, 0, nScreenWidth, nScreenHeight, desktopGuard.get(), left, top, SRCCOPY|CAPTUREBLT))
    {
        // throw std::runtime_error("CaptureDesktop: BitBlt failed");
    }
}


void SpliceImages( ScreenShooter::CDisplayHandlesPool * pHdcPool
                        , CDCGuard &captureGuard
                        , CBitMapGuard & bmpGuard
                        , HGDIOBJ & originalBmp
                        , int * width
                        , int * height)
{
    HDC hDesktopDC = GetDC(NULL);
    CDCGuard desktopGuard(hDesktopDC);

    unsigned int nScreenWidth = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    unsigned int nScreenHeight = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    * width = nScreenWidth;
    * height = nScreenHeight;

    HDC hCaptureDC = CreateCompatibleDC(desktopGuard.get());
    if (!hCaptureDC)
    {
        // throw std::runtime_error("SpliceImages: CreateCompatibleDC failed");
    }
    captureGuard.reset(hCaptureDC);

    HBITMAP hCaptureBmp = CreateCompatibleBitmap(desktopGuard.get(), nScreenWidth, nScreenHeight);
    if(!hCaptureBmp)
    {
        // throw std::runtime_error("SpliceImages: CreateCompatibleBitmap failed");
    }
    bmpGuard.reset(hCaptureBmp);

    originalBmp = SelectObject(hCaptureDC, hCaptureBmp);

    if (!originalBmp || (originalBmp == (HBITMAP)HGDI_ERROR))
    {
        // throw std::runtime_error("SpliceImages: SelectObject failed");
    }

    // Calculating coordinates shift if any monitor has negative coordinates
    long shiftLeft = 0;
    long shiftTop = 0;
    for(ScreenShooter::HDCPoolType::iterator it = pHdcPool->begin(); it != pHdcPool->end(); ++it)
    {
        if( it->second.left < shiftLeft)
            shiftLeft = it->second.left;
        if(it->second.top < shiftTop)
            shiftTop = it->second.top;
    }

    for(ScreenShooter::HDCPoolType::iterator it = pHdcPool->begin(); it != pHdcPool->end(); ++it)
    {
        if (!BitBlt(hCaptureDC, it->second.left - shiftLeft, it->second.top - shiftTop, it->second.right - it->second.left, it->second.bottom - it->second.top, it->first, 0, 0, SRCCOPY))
        {
            // throw std::runtime_error("SpliceImages: BitBlt failed");
        }
    }
}


#endif
