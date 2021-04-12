#include "vac_dumper.h"

DWORD _stdcall init(LPVOID)
{
	g_vac_dumper.initialize(GetModuleHandleA(nullptr));
	g_vac_dumper.attach();
	return 0;
}


BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		//DisableThreadLibraryCalls(hinstDLL);
		CreateThread(nullptr, 0, init, nullptr, 0, nullptr);
	}

	return TRUE;
}
