#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "resource.h"

//#define _WIN32_WINNT                    0x0300

#define LVM_SETEXTENDEDLISTVIEWSTYLE    (LVM_FIRST + 54)
#define LVS_EX_GRIDLINES                0x00000001
#define LVS_EX_SUBITEMIMAGES            0x00000002
#define LVS_EX_CHECKBOXES               0x00000004
#define LVS_EX_TRACKSELECT              0x00000008
#define LVS_EX_HEADERDRAGDROP           0x00000010
#define LVS_EX_FULLROWSELECT            0x00000020
#define LVS_EX_ONECLICKACTIVATE         0x00000040
#define LVS_EX_TWOCLICKACTIVATE         0x00000080
#define LVS_EX_DOUBLEBUFFER             0x00010000

#define UPDATE_PERIOD                   1000
#define REMOTE_THREAD_INJECTION         1
#define INSTALL_FUNCTION_HOOK           2
#define IMAGE_NAME_WIDTH                254
#define PID_WIDTH                       40
#define SHOW_ERROR(msg)                 MessageBox(NULL, msg, "Error", MB_ICONERROR | MB_OK);
#define SHOW_SUCCESS(msg)               MessageBox(NULL, msg, "DLL Injector", MB_ICONASTERISK | MB_OK);
#define IS_CHECKED(id)                  (SendDlgItemMessage(hwndDlg, id, BM_GETCHECK, (WPARAM) 0, (LPARAM) 0))

HINSTANCE   g_hInst;
HWND        g_hProcessList;
HWND        g_hMain;
MMRESULT    g_timerEvent;
BOOL        g_isAutoRefreshEnabled = TRUE;
int         g_injectMethod = REMOTE_THREAD_INJECTION;
char        g_szBuffer[MAX_PATH];
char*       g_dllPath;

/* -------------------------------------------------
   Set up list of active processes.
   The user chooses a target process from this list.
   ------------------------------------------------- */
void setupProcessList(HWND hwnd)
{
    if (!hwnd) {
        return;
    }

    char imageNameTitle[] = "Image Name";
    char pidTitle[]       = "PID";

    LVCOLUMN LvCol;
    ZeroMemory(&LvCol, sizeof (LVCOLUMN));
    LvCol.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    SendMessage(hwnd, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);

    LvCol.pszText = imageNameTitle;
    LvCol.cx      = IMAGE_NAME_WIDTH;
    SendMessage(hwnd, LVM_INSERTCOLUMN, 0, (LPARAM) &LvCol);

    LvCol.pszText = pidTitle;
    LvCol.cx      = PID_WIDTH;
    SendMessage(hwnd, LVM_INSERTCOLUMN, 1, (LPARAM) &LvCol);
}

/* --------------------------------
   Update list of active processes.
   -------------------------------- */
BOOL updateProcessList(HWND hwnd)
{
    if (!hwnd) {
        return FALSE;
    }

    LockWindowUpdate(hwnd);

    LVITEM LvItem;
    memset(&LvItem, 0, sizeof (LVITEM));
    LvItem.mask = LVIF_TEXT;
    LvItem.cchTextMax = 256;
    LvItem.iItem = 0;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof (PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!snapshot) {
        return FALSE;
    }

    char *tmp = (char*) calloc(5, sizeof (char));
    if (!tmp) {
        CloseHandle(snapshot);
        return FALSE;
    }

    if (Process32First(snapshot, &entry)) {
        SendMessage(hwnd, LVM_DELETEALLITEMS, 0, 0);

        // Iterate over running processes and add to process list
        while (Process32Next(snapshot, &entry)) {
            // Image name
            LvItem.iSubItem = 0;
            LvItem.pszText = entry.szExeFile;
            SendMessage(hwnd, LVM_INSERTITEM, 0, (LPARAM) &LvItem);

            // Process ID
            LvItem.iSubItem = 1;
            sprintf(tmp, "%lu", entry.th32ProcessID);
            LvItem.pszText = tmp;
            SendMessage(hwnd, LVM_SETITEM, 0, (LPARAM) &LvItem);
        }
    }

    free(tmp);
    CloseHandle(snapshot);
    //ListView_SetItemState(hwnd, 0, LVIS_FOCUSED | LVIS_SELECTED, 0x000F);
    LockWindowUpdate(NULL);
}

/* --------------------------------------------
   Get PID of target process from process list.
   -------------------------------------------- */
int getTargetProcessId(HWND hwnd, char *targetProcessId)
{
    if (!hwnd || !targetProcessId) {
        return 0;
    }

    // Iterate over process list to locate PID
    DWORD dwSelectedItem = SendMessage(hwnd, LVM_GETNEXTITEM, (WPARAM) -1, (LPARAM) LVNI_SELECTED);
    while (dwSelectedItem == -1) {
        dwSelectedItem = SendMessage(hwnd, LVM_GETNEXTITEM, (WPARAM) dwSelectedItem, (LPARAM) LVNI_SELECTED);
    }

    if(dwSelectedItem == -1) {
        return -1;
    }

    LVITEM LvItem;
    LvItem.mask         = LVIF_TEXT;
    LvItem.iItem        = dwSelectedItem;
    LvItem.iSubItem     = 1;
    LvItem.pszText      = targetProcessId;
    LvItem.cchTextMax   = 5;

    SendMessage(hwnd, LVM_GETITEM, (WPARAM) 0, (LPARAM) &LvItem);

    return atoi(LvItem.pszText);
}

/* ---------------------------------------
   Get path of DLL to inject into process.
   --------------------------------------- */
char* getDllPath(HWND hwndMain)
{
    if (!hwndMain) {
        return NULL;
    }

    char* dllPath = (char*) calloc(MAX_PATH, sizeof (char));
    OPENFILENAME ofn;

    ZeroMemory(&ofn, sizeof (OPENFILENAME));
    ofn.lStructSize = sizeof (OPENFILENAME);
    ofn.hwndOwner   = hwndMain;
    ofn.lpstrFilter = "Dynamic Linked Libraries\0*.dll*\0";
    ofn.lpstrFile   = dllPath;
    ofn.lpstrTitle  = "Select DLL";
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_EXPLORER | OFN_FILEMUSTEXIST;

    ZeroMemory(g_dllPath, sizeof (dllPath));
    GetOpenFileName(&ofn);

    return dllPath;
}

/* ----------------------------------------------------------------------------
   Inject DLL into target process.
   This function is called if user has selected remote thread injection method.
   ---------------------------------------------------------------------------- */
BOOL injectDll(DWORD targetProcessId, char *g_dllPath)
{
    if (!targetProcessId || !g_dllPath) {
        return FALSE;
    }

    // Obtain handle of target process
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_VM_READ, FALSE, targetProcessId);
    if (!hProcess) {
        SHOW_ERROR("Error opening process!");
        return FALSE;
    }

    // Allocate memory in target process
    DWORD dwMemSize = lstrlen(g_dllPath) + 1;
    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, dwMemSize,
        MEM_COMMIT, PAGE_READWRITE);
    if (!lpBaseAddress) {
        SHOW_ERROR("Error allocating memory!");
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write to target process address space
    if (!WriteProcessMemory(hProcess, lpBaseAddress, g_dllPath, dwMemSize, NULL)) {
        SHOW_ERROR("Error writing memory!");
        VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Load kernel32.dll
    HMODULE hDll = LoadLibrary(TEXT("kernel32.dll"));
    if (!hDll) {
        SHOW_ERROR("Error loading kernel32.dll!");
        VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Obtain address of LoadLibraryA() function which is called to load the DLL
    FARPROC lpFuncAddress = GetProcAddress(hDll, TEXT("LoadLibraryA"));
    if (!lpFuncAddress) {
        SHOW_ERROR("Error retrieving LoadLibraryA() address!");
        FreeLibrary(hDll);
        VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Load the DLL into the target process address space
    LPVOID hRemoteThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE) lpFuncAddress, lpBaseAddress, 0, NULL);
    if (!hRemoteThread) {
        SHOW_ERROR("Error creating remote thread!");
        FreeLibrary(hDll);
        VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);

    CloseHandle(hRemoteThread);
    FreeLibrary(hDll);
    VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return TRUE;
}

/* --------------------------------------------------------------------------
   Install a function hook into target thread.
   This function is called if user has selected install function hook method.
   -------------------------------------------------------------------------- */
BOOL hookDll(DWORD targetProcessId, char *g_dllPath)
{
    if (!targetProcessId || !g_dllPath) {
        return FALSE;
    }

    // This function contains bugs, doesn't work!

    HMODULE hDll = LoadLibrary(g_dllPath);
    if (!hDll) {
        SHOW_ERROR("Error loading DLL!");
        return FALSE;
    }

    HOOKPROC funcAddr = (HOOKPROC) GetProcAddress(hDll, "TestProc");
    if (!funcAddr) {
        SHOW_ERROR("Error retrieving address of DLL function!");
        FreeLibrary(hDll);
        return FALSE;
    }

    HHOOK hDllHook = SetWindowsHookEx(WH_KEYBOARD, funcAddr, hDll, 3492);
    if (!hDllHook) {
        SHOW_ERROR("Error creating function hook!");
//        free(funcAddr);
        FreeLibrary(hDll);
        return FALSE;
    }

    UnhookWindowsHookEx(hDllHook);
    FreeLibrary(hDll);
}

/* ---------------------------------------------------------------------------
   Check if running on Windows NT.
   This function is called to enable/disable the install function hook option.
   --------------------------------------------------------------------------- */
BOOL isWindowsNT()
{
   DWORD dwVersion = GetVersion();
   //DWORD dwMajorVersion = (DWORD) (LOBYTE(LOWORD(dwVersion)));
   //DWORD dwMinorVersion = (DWORD) (HIBYTE(LOWORD(dwVersion)));
   return (dwVersion < 0x80000000);
}

void CALLBACK timerCallback(UINT uID, UINT uMsg, DWORD dwUser, DWORD dw1, DWORD dw2)
{
    if (g_isAutoRefreshEnabled) {
        int iPos = SendMessage(g_hMain, LVM_GETNEXTITEM,(WPARAM) -1, (LPARAM) LVNI_SELECTED);

        while (iPos == -1) {
            iPos = SendMessage(g_hMain, LVM_GETNEXTITEM,(WPARAM) iPos, (LPARAM) LVNI_SELECTED);
        }

        updateProcessList(g_hMain);
        ListView_SetItemState(g_hMain, iPos, LVIS_FOCUSED | LVIS_SELECTED, 0x000F);
    }
}

BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    PAINTSTRUCT ps;
    HDC hdc;
    g_dllPath = (char*) calloc(MAX_PATH, sizeof(char));

    switch(uMsg) {
    case WM_INITDIALOG:
    {
        // Check if user is running Windows NT
        if (!isWindowsNT()) {
            EnableWindow(GetDlgItem(hwndDlg, IDC_REMOTE_THREAD_INJECTION), FALSE);
            //SetDlgItemText(hwndDlg, IDC_REMOTE_THREAD_INJECTION, "Remote thread injection (NT only)");
            SendDlgItemMessage(hwndDlg, IDC_INSTALL_FUNCTION_HOOK, BM_SETCHECK, (WPARAM)BST_CHECKED, (LPARAM)0);
        } else {
            SendDlgItemMessage(hwndDlg, IDC_REMOTE_THREAD_INJECTION, BM_SETCHECK, (WPARAM)BST_CHECKED, (LPARAM)0);
        }

        SendDlgItemMessage(hwndDlg, IDC_AUTO_REFRESH, BM_SETCHECK, (WPARAM) BST_CHECKED, (LPARAM) 0);

        // Set up timer/process list
        g_hMain      = GetDlgItem(hwndDlg, IDC_PROCESS_LIST);
        g_timerEvent = timeSetEvent(UPDATE_PERIOD, 0, timerCallback, 0, TIME_PERIODIC);
        setupProcessList(GetDlgItem(hwndDlg, IDC_PROCESS_LIST));
        updateProcessList(GetDlgItem(hwndDlg, IDC_PROCESS_LIST));
    }
    return TRUE;
    //break;

    case WM_CLOSE:
    {
        EndDialog(hwndDlg, 0);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
            case IDC_CLOSE:
                ExitProcess(0);
                break;

            case IDC_SELECT_DLL:
                // User selects DLL
                g_dllPath = getDllPath(hwndDlg);

                if (lstrlen(g_dllPath) > 0) {
                    SetDlgItemText(hwndDlg, IDC_DLL_PATH, g_dllPath);
                    EnableWindow(GetDlgItem(hwndDlg, IDC_INJECT_DLL), TRUE);
                }
                break;

            case IDC_INJECT_DLL:
                {
                    int targetProcessId = getTargetProcessId(GetDlgItem(hwndDlg, IDC_PROCESS_LIST), g_szBuffer);
                    if (g_injectMethod == REMOTE_THREAD_INJECTION) {
                        // Use DLL injection method
                        injectDll(targetProcessId, g_dllPath);
                    } else if (g_injectMethod == INSTALL_FUNCTION_HOOK) {
                        // Use function hook method
                        hookDll(getTargetProcessId(GetDlgItem(hwndDlg, IDC_PROCESS_LIST), g_szBuffer), g_dllPath);
                    }
                }
                break;

            case IDC_UNLOAD_DLL:
                //ExitProcess(0);
                break;

            case IDC_REFRESH:
                updateProcessList(GetDlgItem(hwndDlg, IDC_PROCESS_LIST));
                break;

            case WM_NCHITTEST:
                {
                    UINT uHitTest = DefWindowProc(hwndDlg, WM_NCHITTEST, wParam, lParam);
                    if(uHitTest == HTCLIENT) {
                        return HTCAPTION;
                    } else {
                        return uHitTest;
                    }
                }
                break;

            case IDC_AUTO_REFRESH:
//                if (SendDlgItemMessage(hwndDlg, IDC_AUTO_REFRESH, BM_GETCHECK, (WPARAM) 0, (LPARAM) 0)) {
//                    g_isAutoRefreshEnabled = TRUE;
//                } else {
//                    g_isAutoRefreshEnabled = FALSE;
//                }
                g_isAutoRefreshEnabled = (IS_CHECKED(IDC_AUTO_REFRESH)) ? TRUE : FALSE;
                break;

            case IDC_REMOTE_THREAD_INJECTION:
                g_injectMethod = REMOTE_THREAD_INJECTION;
                break;

            case IDC_INSTALL_FUNCTION_HOOK:
                g_injectMethod = INSTALL_FUNCTION_HOOK;
                break;
        }
    }
    return TRUE;
    }
    return FALSE;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    g_hInst = hInstance;
    InitCommonControls();
    return DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, (DLGPROC) DlgMain);
}
