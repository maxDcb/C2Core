#include "ScreenShooter.h"

#include <iostream>

using namespace guards;

void CreateBitmapFinal(std::vector<unsigned char> & data, CDCGuard &captureGuard, CBitMapGuard & bmpGuard, HGDIOBJ & originalBmp, int nScreenWidth, int nScreenHeight);
void CaptureDesktop(CDCGuard &desktopGuard, CDCGuard &captureGuard, CBitMapGuard & bmpGuard, HGDIOBJ & originalBmp, int * width, int * height, int left, int top);
void SpliceImages(ScreenShooter::CDisplayHandlesPool * pHdcPool, CDCGuard &captureGuard, CBitMapGuard & bmpGuard, HGDIOBJ & originalBmp, int * width, int * height);

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

    CreateBitmapFinal(dataScreen, captureGuard, bmpGuard, originalBmp, width, height);
}

void CreateBitmapFinal(std::vector<unsigned char> & data, CDCGuard &captureGuard, CBitMapGuard & bmpGuard, HGDIOBJ & originalBmp, int nScreenWidth, int nScreenHeight)
{
    // save data to buffer
    unsigned char charBitmapInfo[sizeof(BITMAPINFOHEADER) + 256 * sizeof(RGBQUAD)] = {0};
    LPBITMAPINFO lpbi = (LPBITMAPINFO)charBitmapInfo;
    lpbi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    lpbi->bmiHeader.biHeight = nScreenHeight;
    lpbi->bmiHeader.biWidth = nScreenWidth;
    lpbi->bmiHeader.biPlanes = 1; 
    lpbi->bmiHeader.biBitCount = 32;
    lpbi->bmiHeader.biCompression = BI_RGB;

    SelectObject(captureGuard.get(), originalBmp); 

    std::cout << "gogo" << std::endl;

    if (!GetDIBits(captureGuard.get(), bmpGuard.get(), 0, nScreenHeight, NULL, lpbi, DIB_RGB_COLORS))
    {
        int err = GetLastError();
        // throw std::runtime_error("CreateBitmapFinal: GetDIBits failed");
    }

    DWORD ImageSize = lpbi->bmiHeader.biSizeImage; //known image size

    DWORD PalEntries = 3;
    if (lpbi->bmiHeader.biCompression != BI_BITFIELDS) 
        PalEntries = (lpbi->bmiHeader.biBitCount <= 8) ?(int)(1 << lpbi->bmiHeader.biBitCount) : 0;
    if (lpbi->bmiHeader.biClrUsed) 
        PalEntries = lpbi->bmiHeader.biClrUsed; 
    //known pal entrys count

    //all resize
    data.resize(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + PalEntries * sizeof(RGBQUAD) + ImageSize);
    //set screenshot size

    DWORD imageOffset = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + PalEntries * sizeof(RGBQUAD);
    DWORD infoHeaderOffset = sizeof(BITMAPFILEHEADER);
    BITMAPFILEHEADER * pFileHeader = (BITMAPFILEHEADER *)&data[0];
    pFileHeader->bfType            = 19778; // always the same, 'BM'
    pFileHeader->bfReserved1    = pFileHeader->bfReserved2 = 0; 
    pFileHeader->bfOffBits        = imageOffset;
    pFileHeader->bfSize            = ImageSize;

    if (!GetDIBits(captureGuard.get(), bmpGuard.get(), 0, nScreenHeight, &data[imageOffset], lpbi, DIB_RGB_COLORS))
    {
        // throw std::runtime_error("CreateBitmapFinal: GetDIBits failed");
    }

    memcpy(&data[sizeof(BITMAPFILEHEADER)], &lpbi->bmiHeader, sizeof(BITMAPINFOHEADER));

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