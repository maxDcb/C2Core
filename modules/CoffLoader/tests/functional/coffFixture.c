__declspec(dllimport) void BeaconOutput(int type, char* data, int length);

void go(char* args, unsigned long length)
{
    (void)args;
    (void)length;
    char marker[] = "C2CORE_COFF_OK";
    BeaconOutput(0, marker, sizeof(marker) - 1);
}
