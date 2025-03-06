#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <map>
#include <Iphlpapi.h>
#include <winioctl.h>
#include <WbemIdl.h>
#include <comdef.h>
#include <Setupapi.h>
#include <ntddscsi.h>
#include <shlobj.h>
#include <sstream>
#include <memory>
#include <bcrypt.h>
#include <TlHelp32.h>
#include <algorithm>
#include <chrono>
#include <functional>
#include <thread>
#include <mutex>
#include <fstream>
#include <Psapi.h>
#include <devguid.h>    
#include <initguid.h>   
#include <winternl.h>   
#include <powrprof.h>
#include <intrin.h>
#include <cstdint>
#include <codecvt> 
#include <locale>  


#define IMGUI_IMPL_WIN32_DISABLE_GAMEPAD
#include "imGui/imgui_impl_dx11.h"
#include "imGui/imgui_impl_win32.h"
#include "imGui/imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>
#include "imGui/imgui.h"
#include "imGui/imgui_internal.h"
#include "imGui/imgui.h"

#ifndef GUID_DEVINTERFACE_DISK
DEFINE_GUID(GUID_DEVINTERFACE_DISK, 0x53f56307L, 0xb6bf, 0x11d0, 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b);
#endif


#define _WIN32_DCOM
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")


typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* pNtSetSystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength
    );


static ID3D11Device* g_pd3dDevice = NULL;
static ID3D11DeviceContext* g_pd3dDeviceContext = NULL;
static IDXGISwapChain* g_pSwapChain = NULL;
static ID3D11RenderTargetView* g_mainRenderTargetView = NULL;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);


#define SPOOFER_VERSION "4.0.0"
#define MAX_ERROR_LENGTH 1024
#define MAX_RETRY_COUNT 3
#define AUTO_RESTORE_KEY "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define BACKUP_FILENAME "hwid_backup.enc"


#ifndef STORAGE_PROPERTY_ID_DEFINED
typedef enum _STORAGE_PROPERTY_ID {
    StorageDeviceProperty,
    StorageAdapterProperty,
    StorageMiniportProperty,
    StorageAccessAlignmentProperty,
    StorageDeviceSeekPenaltyProperty,
    StorageDeviceTrimProperty,
    StorageDeviceWriteAggregationProperty,
    StorageDeviceDeviceTelemetryProperty,
    StorageDeviceLBProvisioningProperty,
    StorageDevicePowerProperty,
    StorageDeviceCopyOffloadProperty,
    StorageDeviceResiliencyProperty,
    StorageDeviceMediumProductType,
    StorageDeviceNumaProperty,
    StorageDeviceZonedDeviceProperty,
    StorageDeviceWriteCacheProperty,
    StorageDeviceIoQosProperty,
    StorageDeviceSelfEncryptionProperty,
    StorageDeviceDurableWriteCacheProperty,
    StorageDeviceTieringProperty,
    StorageDeviceTelemetry2Property,
    StorageDeviceFaultDomainPropertyMax,
    StorageAdapterTelemetryProperty,
    StorageDeviceIopsProperty,
    StorageDeviceMaxProperty
} STORAGE_PROPERTY_ID;
#define STORAGE_PROPERTY_ID_DEFINED
#endif

#ifndef STORAGE_QUERY_TYPE_DEFINED
typedef enum _STORAGE_QUERY_TYPE {
    PropertyStandardQuery,
    PropertyExistsQuery,
    PropertyNameQuery,
    PropertyMaximumQueryType
} STORAGE_QUERY_TYPE;
#define STORAGE_QUERY_TYPE_DEFINED
#endif

#define DiskControllerEnum StorageAdapterProperty 


struct OperationResult {
    bool success;
    std::string message;

    OperationResult(bool s = false, const std::string& msg = "")
        : success(s), message(msg) {
    }
};


class Logger {
private:
    std::stringstream logBuffer;
    std::mutex logMutex;
    bool enableFileLogging;
    std::string logFilePath;

public:
    Logger() : enableFileLogging(false), logFilePath("spoofer_log.txt") {}

    void EnableFileLogging(bool enable, const std::string& filePath = "spoofer_log.txt") {
        std::lock_guard<std::mutex> lock(logMutex);
        enableFileLogging = enable;
        logFilePath = filePath;
    }

    void AddLog(const std::string& message) {
        std::lock_guard<std::mutex> lock(logMutex);

        
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        tm localTime;
        localtime_s(&localTime, &time);

        char timeBuffer[80];
        strftime(timeBuffer, sizeof(timeBuffer), "[%Y-%m-%d %H:%M:%S] ", &localTime);

        
        logBuffer << timeBuffer << message << std::endl;

        
        if (enableFileLogging) {
            std::ofstream logFile(logFilePath, std::ios::app);
            if (logFile.is_open()) {
                logFile << timeBuffer << message << std::endl;
                logFile.close();
            }
        }

        
        std::string dbgStr = std::string(timeBuffer) + message + "\n";
        OutputDebugStringA(dbgStr.c_str());
    }


    std::string GetLogs() {
        std::lock_guard<std::mutex> lock(logMutex);
        return logBuffer.str();
    }

    void ClearLogs() {
        std::lock_guard<std::mutex> lock(logMutex);
        logBuffer.str("");
        logBuffer.clear();
    }
};


Logger g_Logger;


void AddLog(const std::string& message) {
    g_Logger.AddLog(message);
}


void DisplayLogs() {
    ImGui::BeginChild("Logs", ImVec2(0, 200), true);
    ImGui::TextWrapped("%s", g_Logger.GetLogs().c_str());
    ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();

    if (ImGui::Button("Effacer les logs")) {
        g_Logger.ClearLogs();
    }
    ImGui::SameLine();
    static bool fileLogging = false;
    if (ImGui::Checkbox("Activer logging fichier", &fileLogging)) {
        g_Logger.EnableFileLogging(fileLogging);
    }
}


struct OriginalValues {
    
    std::wstring smbiosSerial;
    std::wstring smbiosManufacturer;
    std::wstring smbiosProduct;
    std::wstring smbiosVersion;

    
    struct DiskInfo {
        std::string path;
        std::string serial;
        std::string model;
        std::string firmware;
    };
    std::vector<DiskInfo> diskInfo;

    
    std::map<std::wstring, std::wstring> macAddresses;

    
    struct {
        std::string deviceID;
        std::string vendorID;
        std::string subsysID;
        std::string hardwareID;
        std::string pnpID;
        std::string uuid;
    } gpuInfo;

    
    struct {
        std::string machineGuid;
        std::string productID;
        DWORD installDate;
        std::string digitalProductID;
        std::string hwProfileGuid;
    } windowsInfo;

    
    struct {
        std::vector<uint8_t> tpmEndorsementKey;
        std::string hwProfile;
        std::string deviceUniqueID;
    } securityInfo;

    
    std::map<std::string, std::string> miscIdentifiers;

    
    bool SaveToFile(const std::string& filename, const std::string& password) {
        try {
            
            std::stringstream dataStream;

            
            dataStream << "SMBIOS_SERIAL=" << std::string(smbiosSerial.begin(), smbiosSerial.end()) << std::endl;
            dataStream << "SMBIOS_MANUFACTURER=" << std::string(smbiosManufacturer.begin(), smbiosManufacturer.end()) << std::endl;
            dataStream << "SMBIOS_PRODUCT=" << std::string(smbiosProduct.begin(), smbiosProduct.end()) << std::endl;
            dataStream << "SMBIOS_VERSION=" << std::string(smbiosVersion.begin(), smbiosVersion.end()) << std::endl;

            
            dataStream << "DISK_COUNT=" << diskInfo.size() << std::endl;
            for (size_t i = 0; i < diskInfo.size(); i++) {
                dataStream << "DISK_" << i << "_PATH=" << diskInfo[i].path << std::endl;
                dataStream << "DISK_" << i << "_SERIAL=" << diskInfo[i].serial << std::endl;
                dataStream << "DISK_" << i << "_MODEL=" << diskInfo[i].model << std::endl;
                dataStream << "DISK_" << i << "_FIRMWARE=" << diskInfo[i].firmware << std::endl;
            }

            
            dataStream << "MAC_COUNT=" << macAddresses.size() << std::endl;
            int macIndex = 0;
            for (const auto& mac : macAddresses) {
                dataStream << "MAC_" << macIndex << "_PATH=" << std::string(mac.first.begin(), mac.first.end()) << std::endl;
                dataStream << "MAC_" << macIndex << "_VALUE=" << std::string(mac.second.begin(), mac.second.end()) << std::endl;
                macIndex++;
            }

            
            dataStream << "GPU_DEVICE_ID=" << gpuInfo.deviceID << std::endl;
            dataStream << "GPU_VENDOR_ID=" << gpuInfo.vendorID << std::endl;
            dataStream << "GPU_SUBSYS_ID=" << gpuInfo.subsysID << std::endl;
            dataStream << "GPU_HARDWARE_ID=" << gpuInfo.hardwareID << std::endl;
            dataStream << "GPU_PNP_ID=" << gpuInfo.pnpID << std::endl;
            dataStream << "GPU_UUID=" << gpuInfo.uuid << std::endl;

            
            dataStream << "WINDOWS_MACHINE_GUID=" << windowsInfo.machineGuid << std::endl;
            dataStream << "WINDOWS_PRODUCT_ID=" << windowsInfo.productID << std::endl;
            dataStream << "WINDOWS_INSTALL_DATE=" << windowsInfo.installDate << std::endl;
            dataStream << "WINDOWS_DIGITAL_PRODUCT_ID=" << windowsInfo.digitalProductID << std::endl;
            dataStream << "WINDOWS_HW_PROFILE_GUID=" << windowsInfo.hwProfileGuid << std::endl;

            
            std::string data = dataStream.str();

            
            std::string encryptedData;
            for (size_t i = 0; i < data.length(); i++) {
                BYTE keyByte = static_cast<BYTE>(password[i % password.length()]);
                encryptedData += data[i] ^ keyByte;
            }

            
            std::ofstream outFile(filename, std::ios::binary);
            if (!outFile) {
                return false;
            }

            
            if (encryptedData.length() > std::numeric_limits<std::streamsize>::max()) {
                AddLog("Erreur: La taille des données est trop grande pour être écrite.");
                outFile.close();
                return false;
            }

            outFile.write(encryptedData.c_str(), static_cast<std::streamsize>(encryptedData.length()));
            outFile.close();

            return true;
        }
        catch (const std::exception& e) {
            AddLog("Erreur lors de la sauvegarde des valeurs: " + std::string(e.what()));
            return false;
        }
    }

    bool LoadFromFile(const std::string& filename, const std::string& password) {
        try {
            
            std::ifstream inFile(filename, std::ios::binary);
            if (!inFile) {
                return false;
            }

            
            std::stringstream buffer;
            buffer << inFile.rdbuf();
            std::string encryptedData = buffer.str();
            inFile.close();

            
            std::string data;
            for (size_t i = 0; i < encryptedData.length(); i++) {
                BYTE keyByte = static_cast<BYTE>(password[i % password.length()]);
                data += encryptedData[i] ^ keyByte;
            }

            
            std::istringstream dataStream(data);
            std::string line;
            std::map<std::string, std::string> values;

            while (std::getline(dataStream, line)) {
                size_t pos = line.find('=');
                if (pos != std::string::npos) {
                    std::string key = line.substr(0, pos);
                    std::string value = line.substr(pos + 1);
                    values[key] = value;
                }
            }

            
            smbiosSerial = std::wstring(values["SMBIOS_SERIAL"].begin(), values["SMBIOS_SERIAL"].end());
            smbiosManufacturer = std::wstring(values["SMBIOS_MANUFACTURER"].begin(), values["SMBIOS_MANUFACTURER"].end());
            smbiosProduct = std::wstring(values["SMBIOS_PRODUCT"].begin(), values["SMBIOS_PRODUCT"].end());
            smbiosVersion = std::wstring(values["SMBIOS_VERSION"].begin(), values["SMBIOS_VERSION"].end());

            
            int diskCount = std::stoi(values["DISK_COUNT"]);
            diskInfo.clear();
            for (int i = 0; i < diskCount; i++) {
                DiskInfo info;
                info.path = values["DISK_" + std::to_string(i) + "_PATH"];
                info.serial = values["DISK_" + std::to_string(i) + "_SERIAL"];
                info.model = values["DISK_" + std::to_string(i) + "_MODEL"];
                info.firmware = values["DISK_" + std::to_string(i) + "_FIRMWARE"];
                diskInfo.push_back(info);
            }

            
            int macCount = std::stoi(values["MAC_COUNT"]);
            macAddresses.clear();
            for (int i = 0; i < macCount; i++) {
                std::wstring path = std::wstring(values["MAC_" + std::to_string(i) + "_PATH"].begin(),
                    values["MAC_" + std::to_string(i) + "_PATH"].end());
                std::wstring value = std::wstring(values["MAC_" + std::to_string(i) + "_VALUE"].begin(),
                    values["MAC_" + std::to_string(i) + "_VALUE"].end());
                macAddresses[path] = value;
            }

            
            gpuInfo.deviceID = values["GPU_DEVICE_ID"];
            gpuInfo.vendorID = values["GPU_VENDOR_ID"];
            gpuInfo.subsysID = values["GPU_SUBSYS_ID"];
            gpuInfo.hardwareID = values["GPU_HARDWARE_ID"];
            gpuInfo.pnpID = values["GPU_PNP_ID"];
            gpuInfo.uuid = values["GPU_UUID"];

            
            windowsInfo.machineGuid = values["WINDOWS_MACHINE_GUID"];
            windowsInfo.productID = values["WINDOWS_PRODUCT_ID"];
            windowsInfo.installDate = std::stoul(values["WINDOWS_INSTALL_DATE"]);
            windowsInfo.digitalProductID = values["WINDOWS_DIGITAL_PRODUCT_ID"];
            windowsInfo.hwProfileGuid = values["WINDOWS_HW_PROFILE_GUID"];

            return true;
        }
        catch (const std::exception& e) {
            AddLog("Erreur lors du chargement des valeurs: " + std::string(e.what()));
            return false;
        }
    }
};


OriginalValues originalValues;


void SetModernTheme() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    
    colors[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.10f, 0.12f, 1.00f);
    colors[ImGuiCol_FrameBg] = ImVec4(0.16f, 0.16f, 0.18f, 1.00f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.24f, 0.24f, 0.26f, 1.00f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.32f, 0.32f, 0.34f, 1.00f);
    colors[ImGuiCol_TitleBg] = ImVec4(0.08f, 0.08f, 0.09f, 1.00f);
    colors[ImGuiCol_TitleBgActive] = ImVec4(0.06f, 0.06f, 0.30f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 0.75f);

    
    colors[ImGuiCol_Button] = ImVec4(0.06f, 0.12f, 0.40f, 1.00f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.10f, 0.20f, 0.60f, 1.00f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.16f, 0.32f, 0.90f, 1.00f);

    
    colors[ImGuiCol_Header] = ImVec4(0.08f, 0.16f, 0.48f, 0.31f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.12f, 0.24f, 0.60f, 0.80f);
    colors[ImGuiCol_HeaderActive] = ImVec4(0.16f, 0.32f, 0.72f, 1.00f);
    colors[ImGuiCol_Tab] = ImVec4(0.08f, 0.08f, 0.32f, 0.86f);
    colors[ImGuiCol_TabHovered] = ImVec4(0.16f, 0.16f, 0.48f, 0.80f);
    colors[ImGuiCol_TabActive] = ImVec4(0.20f, 0.20f, 0.60f, 1.00f);

    
    colors[ImGuiCol_CheckMark] = ImVec4(0.00f, 0.80f, 0.80f, 1.00f);
    colors[ImGuiCol_SliderGrab] = ImVec4(0.00f, 0.60f, 0.80f, 1.00f);
    colors[ImGuiCol_SliderGrabActive] = ImVec4(0.00f, 0.80f, 1.00f, 1.00f);

    
    colors[ImGuiCol_ScrollbarBg] = ImVec4(0.02f, 0.02f, 0.02f, 0.53f);
    colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.16f, 0.16f, 0.16f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.24f, 0.24f, 0.24f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.32f, 0.32f, 0.32f, 1.00f);

    
    style.FrameRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.WindowRounding = 6.0f;
    style.ChildRounding = 4.0f;
    style.PopupRounding = 4.0f;
    style.ScrollbarRounding = 9.0f;
    style.TabRounding = 4.0f;

    
    style.WindowPadding = ImVec2(10, 10);
    style.FramePadding = ImVec2(8, 4);
    style.ItemSpacing = ImVec2(10, 8);
    style.ItemInnerSpacing = ImVec2(6, 6);

    
    style.IndentSpacing = 20.0f;
    style.ScrollbarSize = 15.0f;
    style.GrabMinSize = 10.0f;
}


std::string GenerateRandomHWID(size_t length, bool hexOnly = true) {
    const char* charset = hexOnly ? "0123456789ABCDEF" : "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const size_t charsetSize = hexOnly ? 16 : 62;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, charsetSize - 1);

    std::string result;
    result.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        result += charset[dis(gen)];
    }

    return result;
}


std::string GenerateSecureRandomID(size_t length, bool hexOnly = true) {
    if (length > std::numeric_limits<ULONG>::max()) {
        AddLog("Erreur: La longueur demandée est trop grande.");
        return ""; 
    }
    std::vector<BYTE> buffer(length);

    
    if (FAILED(BCryptGenRandom(NULL, buffer.data(), length, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        
        return GenerateRandomHWID(length, hexOnly);
    }

    
    const char* charset = hexOnly ? "0123456789ABCDEF" : "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const size_t charsetSize = hexOnly ? 16 : 62;

    std::string result;
    result.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        result += charset[buffer[i] % charsetSize];
    }

    return result;
}


std::string GenerateWindowsGUID() {
    
    std::string guid = "{";
    guid += GenerateRandomHWID(8);
    guid += "-";
    guid += GenerateRandomHWID(4);
    guid += "-";
    guid += GenerateRandomHWID(4);
    guid += "-";
    guid += GenerateRandomHWID(4);
    guid += "-";
    guid += GenerateRandomHWID(12);
    guid += "}";

    return guid;
}


bool IsUserAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {

        if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }

        FreeSid(administratorsGroup);
    }

    return isAdmin;
}


bool ElevatePrivileges() {
    if (IsUserAdmin()) {
        return true;
    }

    
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    
    SHELLEXECUTEINFOW sei = { 0 }; 
    sei.cbSize = sizeof(SHELLEXECUTEINFOW);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.hwnd = NULL;
    sei.lpVerb = L"runas";
    sei.lpFile = path;
    sei.lpParameters = NULL; 
    sei.lpDirectory = NULL;
    sei.nShow = SW_SHOWNORMAL;
    sei.hInstApp = NULL;

    if (ShellExecuteExW(&sei)) {
        
        ExitProcess(0);
        return true;
    }

    AddLog("Élévation des privilèges échouée. Certaines fonctionnalités ne seront pas disponibles.");
    return false;
}


class AntiCheatProtection {
private:
    std::vector<std::wstring> knownAntiCheatProcesses = {
        L"BEService.exe",      
        L"EasyAntiCheat.exe",  
        L"vgc.exe",            
        L"faceit-anticheat.exe",
        L"PnkBstrA.exe",       
        L"xigncode3.exe",      
        L"wellbia.xem",        
        L"acshield.exe",       
        L"mhyprot2.sys",       
        L"anticheatsys.exe",   
        L"ahnlab.exe",         
        L"gameguard.des",      
        L"taikione.sys",       
        L"themida.exe"         
    };

    std::vector<std::wstring> knownAntiCheatDrivers = {
        L"BEDaisy.sys",        
        L"EasyAntiCheat.sys",  
        L"vgk.sys",            
        L"faceitac.sys",       
        L"bneptune.sys",       
        L"xtrap.sys",          
        L"gameguard.sys",      
        L"wzdrv.sys",          
        L"wdfilter.sys",       
        L"mbamswissarmy.sys"   
    };

    
    void AddRandomDelay() {
        std::random_device rd;
        std::mt19937 gen(rd());

        
        std::uniform_int_distribution<> delayDist(5, 50);

        DWORD randomDelay = static_cast<DWORD>(delayDist(gen));
        Sleep(randomDelay);
    }

public:
    
    bool DetectAntiCheat() {
        bool detected = false;
        std::vector<std::string> detectedSystems;

        
        for (const auto& process : knownAntiCheatProcesses) {
            if (IsProcessRunning(process)) {
                detectedSystems.push_back(std::string(process.begin(), process.end()));
                detected = true;
            }
            AddRandomDelay();  
        }

        
        for (const auto& driver : knownAntiCheatDrivers) {
            if (IsDriverLoaded(driver)) {
                detectedSystems.push_back("Driver: " + std::string(driver.begin(), driver.end()));
                detected = true;
            }
            AddRandomDelay();
        }

        
        if (IsServiceRunning(L"BEService") || IsServiceRunning(L"EasyAntiCheat") ||
            IsServiceRunning(L"vgc") || IsServiceRunning(L"PnkBstrA")) {
            detectedSystems.push_back("Service anti-cheat détecté");
            detected = true;
        }

        
        if (IsDebuggerPresent() || IsBeingDebugged()) {
            detectedSystems.push_back("Debugger détecté");
            detected = true;
        }

        
        if (detected) {
            std::string message = "Systèmes anti-cheat détectés: ";
            for (size_t i = 0; i < detectedSystems.size(); i++) {
                message += detectedSystems[i];
                if (i < detectedSystems.size() - 1) {
                    message += ", ";
                }
            }
            AddLog(message);
        }

        return detected;
    }

    
    bool IsProcessRunning(const std::wstring& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(processName.c_str(), pe32.szExeFile) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return false;
    }

    
    bool IsDriverLoaded(const std::wstring& driverName) {
        DWORD bytesNeeded = 0;
        EnumDeviceDrivers(NULL, 0, &bytesNeeded);

        if (bytesNeeded == 0) return false;

        LPVOID* driverAddresses = (LPVOID*)malloc(bytesNeeded);
        if (driverAddresses == NULL) return false;

        if (EnumDeviceDrivers(driverAddresses, bytesNeeded, &bytesNeeded)) {
            DWORD driverCount = bytesNeeded / sizeof(LPVOID);

            for (DWORD i = 0; i < driverCount; i++) {
                WCHAR driverBaseName[MAX_PATH];
                if (GetDeviceDriverBaseNameW(driverAddresses[i], driverBaseName, MAX_PATH)) {
                    if (_wcsicmp(driverBaseName, driverName.c_str()) == 0) {
                        free(driverAddresses);
                        return true;
                    }
                }
            }
        }

        free(driverAddresses);
        return false;
    }

    
    bool IsServiceRunning(const std::wstring& serviceName) {
        SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (schSCManager == NULL) return false;

        SC_HANDLE schService = OpenServiceW(schSCManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
        if (schService == NULL) {
            CloseServiceHandle(schSCManager);
            return false;
        }

        SERVICE_STATUS_PROCESS ssp;
        DWORD bytesNeeded;

        if (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return ssp.dwCurrentState == SERVICE_RUNNING;
        }

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return false;
    }

    
    bool IsBeingDebugged() {
        
        PPEB pPeb = NULL;

#ifdef _WIN64
        pPeb = (PPEB)__readgsqword(0x60);
#else
        pPeb = (PPEB)__readfsdword(0x30);
#endif

        if (pPeb && pPeb->BeingDebugged) {
            return true;
        }

        
        BOOL isDebuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
        if (isDebuggerPresent) {
            return true;
        }

        
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);

        
        for (volatile int i = 0; i < 1000; i++) {}

        QueryPerformanceCounter(&end);

        
        double milliseconds = 1000.0 * (end.QuadPart - start.QuadPart) / freq.QuadPart;
        if (milliseconds > 10.0) {
            return true;
        }

        return false;
    }

    
    void ApplyProtections() {
        
        if (IsRunningInVM()) {
            AddLog("Détection de machine virtuelle - application de protections supplémentaires");
        }

        
        ObfuscateStrings();

        
        AddRandomDelay();

        
        ProtectCriticalFunctions();
    }

    
    bool IsRunningInVM() {
        
        if (IsProcessRunning(L"vmtoolsd.exe") || 
            IsProcessRunning(L"VBoxService.exe") || 
            IsProcessRunning(L"prl_tools.exe")) { 
            return true;
        }

        
        if (IsDriverLoaded(L"vmci.sys") || 
            IsDriverLoaded(L"VBoxMouse.sys") || 
            IsDriverLoaded(L"prl_fs.sys")) { 
            return true;
        }

        
        if (IsServiceRunning(L"VMTools") ||
            IsServiceRunning(L"VBoxService")) {
            return true;
        }

        
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[256];
            DWORD size = sizeof(buffer);

            if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
                std::string manufacturer(buffer);
                if (manufacturer.find("VMware") != std::string::npos ||
                    manufacturer.find("VirtualBox") != std::string::npos ||
                    manufacturer.find("Xen") != std::string::npos) {
                    RegCloseKey(hKey);
                    return true;
                }
            }
            RegCloseKey(hKey);
        }

        return false;
    }

    
    void ObfuscateStrings() {
        
        
        
        
        
    }

    
    void ProtectCriticalFunctions() {
        
        
        
    }
};


class MemoryProtection {
private:
    struct ProtectedRegion {
        void* address;
        size_t size;
        DWORD originalProtection;
    };

    std::vector<ProtectedRegion> protectedRegions;

public:
    
    bool ProtectMemoryRegion(void* address, size_t size) {
        DWORD oldProtect;
        if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            AddLog("Erreur lors de la protection mémoire: " + std::to_string(GetLastError()));
            return false;
        }

        ProtectedRegion region = { address, size, oldProtect };
        protectedRegions.push_back(region);

        return true;
    }

    
    void RestoreProtections() {
        for (const auto& region : protectedRegions) {
            DWORD oldProtect;
            VirtualProtect(region.address, region.size, region.originalProtection, &oldProtect);
        }

        protectedRegions.clear();
    }

    
    bool EncryptMemoryRegion(void* address, size_t size, const std::string& key) {
        DWORD oldProtect;
        if (!VirtualProtect(address, size, PAGE_READWRITE, &oldProtect)) {
            return false;
        }

        
        BYTE* data = (BYTE*)address;
        for (size_t i = 0; i < size; i++) {
            BYTE keyByte = static_cast<BYTE>(key[i % key.length()]);
            data[i] ^= keyByte;
        }

        
        VirtualProtect(address, size, oldProtect, &oldProtect);

        return true;
    }

    
    bool DecryptMemoryRegion(void* address, size_t size, const std::string& key) {
        
        return EncryptMemoryRegion(address, size, key);
    }

    
    template <size_t N>
    class ObfuscatedString {
    private:
        char buffer[N];
        char key[N];
        bool decrypted;

    public:
        ObfuscatedString(const char* str) : decrypted(false) {
            
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(1, 255);

            for (size_t i = 0; i < N - 1; i++) {
                key[i] = static_cast<char>(static_cast<unsigned char>(dis(gen)));
                buffer[i] = str[i] ^ key[i];
            }
            buffer[N - 1] = '\0';
            key[N - 1] = '\0';
        }

        
        const char* decrypt() {
            if (!decrypted) {
                for (size_t i = 0; i < N - 1; i++) {
                    buffer[i] ^= key[i];
                }
                decrypted = true;
            }
            return buffer;
        }

        
        void encrypt() {
            if (decrypted) {
                for (size_t i = 0; i < N - 1; i++) {
                    buffer[i] ^= key[i];
                }
                decrypted = false;
            }
        }

        ~ObfuscatedString() {
            
            if (decrypted) {
                encrypt();
            }
            memset(buffer, 0, N);
            memset(key, 0, N);
        }
    };
};


void SaveOriginalSMBIOS() {
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        AddLog("Erreur lors de l'initialisation COM");
        return;
    }

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        AddLog("Erreur lors de l'initialisation de la sécurité COM");
        CoUninitialize();
        return;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        AddLog("Erreur lors de la création de l'instance WbemLocator");
        CoUninitialize();
        return;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (SUCCEEDED(hres)) {
        
        hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

        if (FAILED(hres)) {
            AddLog("Erreur lors de la configuration de la sécurité WMI");
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return;
        }

        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_BIOS"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

        if (SUCCEEDED(hres)) {
            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;

            while (pEnumerator) {
                hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) break;

                
                VARIANT vtProp;

                
                VariantInit(&vtProp);
                hres = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
                if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) {
                    originalValues.smbiosSerial = vtProp.bstrVal;
                    AddLog("SMBIOS Serial sauvegardé: " + std::string(originalValues.smbiosSerial.begin(), originalValues.smbiosSerial.end()));
                }
                VariantClear(&vtProp);

                
                VariantInit(&vtProp);
                hres = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
                if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) {
                    originalValues.smbiosManufacturer = vtProp.bstrVal;
                }
                VariantClear(&vtProp);

                
                VariantInit(&vtProp);
                hres = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
                if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) {
                    originalValues.smbiosProduct = vtProp.bstrVal;
                }
                VariantClear(&vtProp);

                
                VariantInit(&vtProp);
                hres = pclsObj->Get(L"Version", 0, &vtProp, 0, 0);
                if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) {
                    originalValues.smbiosVersion = vtProp.bstrVal;
                }
                VariantClear(&vtProp);

                pclsObj->Release();
            }

            if (pEnumerator) {
                pEnumerator->Release();
            }
        }
        else {
            AddLog("Erreur lors de l'exécution de la requête WMI");
        }

        pSvc->Release();
    }
    else {
        AddLog("Erreur lors de la connexion au serveur WMI");
    }

    pLoc->Release();
    CoUninitialize();
}


bool SpoofSMBIOS() {
    if (!IsUserAdmin()) {
        AddLog("L'utilisateur n'a pas les privilèges nécessaires pour modifier le SMBIOS.");
        return false;
    }

    
    if (originalValues.smbiosSerial.empty()) {
        SaveOriginalSMBIOS();
    }

    AddLog("Spoofing SMBIOS...");

    HRESULT hres;
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        AddLog("Erreur lors de l'initialisation COM: " + std::to_string(hres));
        return false;
    }

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        AddLog("Erreur lors de l'initialisation de la sécurité COM: " + std::to_string(hres));
        CoUninitialize();
        return false;
    }

    
    IWbemLocator* pLocRaw = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLocRaw);
    if (FAILED(hres)) {
        AddLog("Erreur lors de la création de l'instance WbemLocator: " + std::to_string(hres));
        CoUninitialize();
        return false;
    }

    std::unique_ptr<IWbemLocator, void(*)(IWbemLocator*)> pLoc(pLocRaw, [](IWbemLocator* p) {
        if (p) p->Release();
        });

    IWbemServices* pSvcRaw = NULL;
    hres = pLoc->ConnectServer(
    _bstr_t(L"ROOT\\CIMV2"),  
    NULL,                     
    NULL,                     
    NULL,                     
    0,                        
    NULL,                     
    0,
    &pSvcRaw                  
);
    if (FAILED(hres)) {
        AddLog("Erreur lors de la connexion au serveur WMI: " + std::to_string(hres));
        CoUninitialize();
        return false;
    }

    std::unique_ptr<IWbemServices, void(*)(IWbemServices*)> pSvc(pSvcRaw, [](IWbemServices* p) {
        if (p) p->Release();
        });

    
    hres = CoSetProxyBlanket(pSvc.get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    if (FAILED(hres)) {
        AddLog("Erreur lors de la configuration de la sécurité WMI: " + std::to_string(hres));
        CoUninitialize();
        return false;
    }

    std::wstring query = L"SELECT * FROM Win32_BIOS";
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

    if (FAILED(hres)) {
        AddLog("Erreur lors de l'exécution de la requête WMI: " + std::to_string(hres));
        CoUninitialize();
        return false;
    }

    bool success = false;

    if (pEnumerator) {
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;

        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            
            std::string newSerial = GenerateSecureRandomID(20);
            std::string newManufacturer = "Generic Systems";
            std::string newProduct = "Virtual Platform " + GenerateRandomHWID(4);
            std::string newVersion = "1." + GenerateRandomHWID(2) + "." + GenerateRandomHWID(3);

            
            _variant_t varSerial(newSerial.c_str());
            _variant_t varManufacturer(newManufacturer.c_str());
            _variant_t varProduct(newProduct.c_str());
            _variant_t varVersion(newVersion.c_str());

            hres = pclsObj->Put(L"SerialNumber", 0, &varSerial, 0);
            if (SUCCEEDED(hres)) {
                hres = pclsObj->Put(L"Manufacturer", 0, &varManufacturer, 0);
            }
            if (SUCCEEDED(hres)) {
                hres = pclsObj->Put(L"Name", 0, &varProduct, 0);
            }
            if (SUCCEEDED(hres)) {
                hres = pclsObj->Put(L"Version", 0, &varVersion, 0);
            }

            if (SUCCEEDED(hres)) {
                hres = pSvc->PutInstance(pclsObj, WBEM_FLAG_UPDATE_ONLY, NULL, NULL);
                if (SUCCEEDED(hres)) {
                    AddLog("SMBIOS modifié avec succès");
                    AddLog("  > Nouveau Serial: " + newSerial);
                    AddLog("  > Nouveau Manufacturer: " + newManufacturer);
                    AddLog("  > Nouveau Product: " + newProduct);
                    AddLog("  > Nouvelle Version: " + newVersion);
                    success = true;
                }
                else {
                    AddLog("Erreur lors de la mise à jour de l'instance BIOS: " + std::to_string(hres));
                }
            }
            else {
                AddLog("Erreur lors de la modification des propriétés BIOS: " + std::to_string(hres));
            }

            pclsObj->Release();
        }

        pEnumerator->Release();
    }

    CoUninitialize();
    return success;
}


void SaveOriginalDiskInfo() {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_DISK, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        AddLog("Erreur lors de l'énumération des disques");
        return;
    }

    SP_DEVICE_INTERFACE_DATA deviceInterfaceData;
    deviceInterfaceData.cbSize = sizeof(deviceInterfaceData);
    DWORD deviceIndex = 0;

    while (SetupDiEnumDeviceInterfaces(hDevInfo, NULL, &GUID_DEVINTERFACE_DISK, deviceIndex, &deviceInterfaceData)) {
        DWORD requiredSize = 0;

        
        SetupDiGetDeviceInterfaceDetail(hDevInfo, &deviceInterfaceData, NULL, 0, &requiredSize, NULL);

        if (requiredSize == 0) {
            deviceIndex++;
            continue;
        }

        PSP_DEVICE_INTERFACE_DETAIL_DATA pDeviceInterfaceDetailData =
            (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(requiredSize);

        if (!pDeviceInterfaceDetailData) {
            deviceIndex++;
            continue;
        }

        pDeviceInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        if (SetupDiGetDeviceInterfaceDetail(hDevInfo, &deviceInterfaceData,
            pDeviceInterfaceDetailData, requiredSize, NULL, NULL)) {

            HANDLE hDrive = CreateFile(pDeviceInterfaceDetailData->DevicePath,
                GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, 0, NULL);

            if (hDrive != INVALID_HANDLE_VALUE) {
                STORAGE_PROPERTY_QUERY spq = { DiskControllerEnum, PropertyStandardQuery };
                STORAGE_DESCRIPTOR_HEADER sdh = { sizeof(STORAGE_DESCRIPTOR_HEADER) }; 

                DWORD bytesReturned = 0;
                if (DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY,
                    &spq, sizeof(spq), &sdh, sizeof(sdh),
                    &bytesReturned, NULL)) {

                    PSTORAGE_DEVICE_DESCRIPTOR pDevDesc =
                        (PSTORAGE_DEVICE_DESCRIPTOR)malloc(sdh.Size);

                    if (pDevDesc) {
                        if (DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY,
                            &spq, sizeof(spq), pDevDesc, sdh.Size,
                            &bytesReturned, NULL)) {

                            OriginalValues::DiskInfo info;
                            char buffer[256]; 

                            
                            int result = WideCharToMultiByte(CP_UTF8, 0, 
                              (LPCWCH)pDeviceInterfaceDetailData->DevicePath, 
                              -1, buffer, sizeof(buffer), NULL, NULL);
                            if (result > 0) {
                                info.path = std::string(buffer); 
                            } else {
                                
                                AddLog("Erreur de conversion de DevicePath en string.");
                            }

                            
                            if (pDevDesc->SerialNumberOffset > 0) {
                                char* serial = ((char*)pDevDesc) + pDevDesc->SerialNumberOffset;
                                info.serial = std::string(serial);
                            }

                            
                            if (pDevDesc->ProductIdOffset > 0) {
                                char* model = ((char*)pDevDesc) + pDevDesc->ProductIdOffset;
                                info.model = std::string(model);
                            }

                            
                            if (pDevDesc->ProductRevisionOffset > 0) {
                                char* firmware = ((char*)pDevDesc) + pDevDesc->ProductRevisionOffset;
                                info.firmware = std::string(firmware);
                            }

                            
                            auto trim = [](std::string& s) {
                                s.erase(0, s.find_first_not_of(" \t\r\n"));
                                s.erase(s.find_last_not_of(" \t\r\n") + 1);
                                };

                            trim(info.serial);
                            trim(info.model);
                            trim(info.firmware);

                            originalValues.diskInfo.push_back(info);

                            AddLog("Disque sauvegardé: " + info.model + ", S/N: " + info.serial);
                        }
                        free(pDevDesc);
                    }
                }
                CloseHandle(hDrive);
            }
        }

        free(pDeviceInterfaceDetailData);
        deviceIndex++;
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
}


bool SpoofDiskID() {
    if (!IsUserAdmin()) {
        AddLog("L'utilisateur n'a pas les privilèges nécessaires pour modifier les ID de disque.");
        return false;
    }

    
    if (originalValues.diskInfo.empty()) {
        SaveOriginalDiskInfo();
    }

    AddLog("Spoofing des identifiants de disque...");

    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_DISK, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        AddLog("Erreur lors de l'obtention des informations sur les disques.");
        return false;
    }

    SP_DEVICE_INTERFACE_DATA deviceInterfaceData;
    deviceInterfaceData.cbSize = sizeof(deviceInterfaceData);
    DWORD deviceIndex = 0;
    bool anySuccess = false;

    while (SetupDiEnumDeviceInterfaces(hDevInfo, NULL, &GUID_DEVINTERFACE_DISK, deviceIndex, &deviceInterfaceData)) {
        DWORD requiredSize = 0;

        
        SetupDiGetDeviceInterfaceDetail(hDevInfo, &deviceInterfaceData, NULL, 0, &requiredSize, NULL);

        if (requiredSize == 0) {
            deviceIndex++;
            continue;
        }

        PSP_DEVICE_INTERFACE_DETAIL_DATA pDeviceInterfaceDetailData =
            (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(requiredSize);

        if (!pDeviceInterfaceDetailData) {
            deviceIndex++;
            continue;
        }

        pDeviceInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        if (SetupDiGetDeviceInterfaceDetail(hDevInfo, &deviceInterfaceData,
            pDeviceInterfaceDetailData, requiredSize, NULL, NULL)) {

            
            std::string newSerial = GenerateSecureRandomID(16);

            
            AddLog("Disque " + std::to_string(deviceIndex) + " - Nouveau S/N: " + newSerial);

            
            
            

            anySuccess = true;
        }

        free(pDeviceInterfaceDetailData);
        deviceIndex++;
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);



    if (anySuccess) {
        AddLog("Spoofing de disque terminé. Remarque: les modifications sont simulées.");
        return true;
    }
    else {
        AddLog("Aucun disque n'a pu être traité.");
        return false;
    }
}


void SaveOriginalMAC() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        DWORD index = 0;
        WCHAR subKeyName[256];
        DWORD subKeyNameSize = 256;

        while (RegEnumKeyExW(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hSubKey;
            std::wstring subKeyPath = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
            subKeyPath += subKeyName;

            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKeyPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                
                WCHAR driverDesc[256] = { 0 };
                DWORD driverDescSize = sizeof(driverDesc);

                if (RegQueryValueExW(hSubKey, L"DriverDesc", NULL, NULL, (LPBYTE)driverDesc, &driverDescSize) == ERROR_SUCCESS) {
                    
                    WCHAR networkAddress[256] = { 0 };
                    DWORD networkAddressSize = sizeof(networkAddress);

                    if (RegQueryValueExW(hSubKey, L"NetworkAddress", NULL, NULL, (LPBYTE)networkAddress, &networkAddressSize) == ERROR_SUCCESS) {
                        
                        originalValues.macAddresses[subKeyPath] = networkAddress;

                        AddLog("MAC sauvegardée pour " + std::string(driverDesc, driverDesc + wcslen(driverDesc)) +
                            ": " + std::string(networkAddress, networkAddress + wcslen(networkAddress)));
                    }
                }
                RegCloseKey(hSubKey);
            }

            index++;
            subKeyNameSize = 256;
        }

        RegCloseKey(hKey);
    }
}


bool SpoofMAC() {
    if (!IsUserAdmin()) {
        AddLog("L'utilisateur n'a pas les privilèges nécessaires pour modifier les adresses MAC.");
        return false;
    }

    
    if (originalValues.macAddresses.empty()) {
        SaveOriginalMAC();
    }

    AddLog("Spoofing des adresses MAC...");

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        AddLog("Erreur: Impossible d'accéder à la clé de registre des adaptateurs réseau.");
        return false;
    }

    DWORD index = 0;
    WCHAR subKeyName[256];
    DWORD subKeyNameSize = 256;
    bool anySuccess = false;

    while (RegEnumKeyExW(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        HKEY hSubKey;
        std::wstring subKeyPath = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
        subKeyPath += subKeyName;

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKeyPath.c_str(), 0, KEY_ALL_ACCESS, &hSubKey) == ERROR_SUCCESS) {
            
            WCHAR driverDesc[256] = { 0 };
            DWORD driverDescSize = sizeof(driverDesc);

            if (RegQueryValueExW(hSubKey, L"DriverDesc", NULL, NULL, (LPBYTE)driverDesc, &driverDescSize) == ERROR_SUCCESS) {
                
                WCHAR componentId[256] = { 0 };
                DWORD componentIdSize = sizeof(componentId);
                bool isPhysical = true;

                if (RegQueryValueExW(hSubKey, L"ComponentId", NULL, NULL, (LPBYTE)componentId, &componentIdSize) == ERROR_SUCCESS) {
                    std::wstring compId = componentId;

                    if (compId.find(L"VEN_") == std::wstring::npos &&
                        (compId.find(L"VPN") != std::wstring::npos ||
                            compId.find(L"VIRTUAL") != std::wstring::npos ||
                            compId.find(L"VM") != std::wstring::npos)) {
                        isPhysical = false;
                    }
                }

                if (isPhysical) {
                    
                    std::string randomMac = GenerateRandomHWID(12);

                    std::wstring newMac;
                    for (size_t i = 0; i < randomMac.length() && i < 12; i += 2) {
                        if (i > 0) newMac += L":";
                        newMac += std::wstring(randomMac.begin() + i, randomMac.begin() + std::min<size_t>(i + 2, randomMac.length()));
                    }

                    
                    if ((newMac[1] - L'0') % 2 != 0) {
                        
                        newMac[1] = ((newMac[1] - L'0') & 0xFE) + L'0';
                    }

                    
                    DWORD newMacSize = static_cast<DWORD>((newMac.length() + 1) * sizeof(WCHAR));
                    if (RegSetValueExW(hSubKey, L"NetworkAddress", 0, REG_SZ, (LPBYTE)newMac.c_str(), newMacSize) == ERROR_SUCCESS) {
                        
                        std::string driverDescStr(driverDesc, driverDesc + wcslen(driverDesc));
                        std::string newMacStr(newMac.begin(), newMac.end());
                        AddLog("Adresse MAC modifiée pour " + driverDescStr + ": " + newMacStr);

                        
                        std::wstring disableCmd = L"netsh interface set interface \""; 
                        disableCmd += driverDesc; 
                        disableCmd += L"\" disabled"; 

                        std::wstring enableCmd = L"netsh interface set interface \""; 
                        enableCmd += driverDesc; 
                        enableCmd += L"\" enabled"; 

                        
                        STARTUPINFOW si = { 0 }; 
                        si.cb = sizeof(STARTUPINFOW);
                        si.dwFillAttribute = 0; 
                        PROCESS_INFORMATION pi;
                        si.dwFlags = STARTF_USESHOWWINDOW;
                        si.wShowWindow = SW_HIDE;

                        
                        if (CreateProcessW(NULL, (LPWSTR)disableCmd.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                            WaitForSingleObject(pi.hProcess, 5000);
                            CloseHandle(pi.hProcess);
                            CloseHandle(pi.hThread);
                            Sleep(1000);

                            
                            if (CreateProcessW(NULL, (LPWSTR)enableCmd.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                                WaitForSingleObject(pi.hProcess, 5000);
                                CloseHandle(pi.hProcess);
                                CloseHandle(pi.hThread);
                                anySuccess = true;
                            }
                        }
                    }
                    else {
                        AddLog("Erreur lors de la modification de l'adresse MAC pour " +
                            std::string(driverDesc, driverDesc + wcslen(driverDesc)));
                    }
                }
            }
            RegCloseKey(hSubKey);
        }

        index++;
        subKeyNameSize = 256;
    }

    RegCloseKey(hKey);

    if (anySuccess) {
        AddLog("Spoofing MAC terminé avec succès.");
        return true;
    }
    else {
        AddLog("Aucune adresse MAC n'a pu être modifiée.");
        return false;
    }
}

void SaveOriginalGPUInfo() {
    HKEY hKey;
    std::vector<std::wstring> gpuPaths;

    
    const WCHAR* basePath = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000";
    gpuPaths.push_back(basePath);

    
    HKEY videoKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Video", 0, KEY_READ, &videoKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        WCHAR subKeyName[256];
        DWORD subKeyNameSize = 256;

        while (RegEnumKeyExW(videoKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            std::wstring videoPath = L"SYSTEM\\CurrentControlSet\\Control\\Video\\";
            videoPath += subKeyName;
            videoPath += L"\\0000";

            HKEY testKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, videoPath.c_str(), 0, KEY_READ, &testKey) == ERROR_SUCCESS) {
                WCHAR buffer[256];
                DWORD bufferSize = sizeof(buffer);

                if (RegQueryValueExW(testKey, L"DriverDesc", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                    gpuPaths.push_back(videoPath);
                }

                RegCloseKey(testKey);
            }

            index++;
            subKeyNameSize = 256;
        }

        RegCloseKey(videoKey);
    }

    
    for (const auto& path : gpuPaths) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            if (originalValues.gpuInfo.deviceID.empty()) {
                char buffer[256];
                DWORD bufferSize = sizeof(buffer);

                
                if (RegQueryValueExA(hKey, "DeviceID", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                    originalValues.gpuInfo.deviceID = buffer;
                    AddLog("GPU DeviceID sauvegardé: " + originalValues.gpuInfo.deviceID);
                }

                
                bufferSize = sizeof(buffer);
                if (RegQueryValueExA(hKey, "VendorID", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                    originalValues.gpuInfo.vendorID = buffer;
                    AddLog("GPU VendorID sauvegardé: " + originalValues.gpuInfo.vendorID);
                }

                
                bufferSize = sizeof(buffer);
                if (RegQueryValueExA(hKey, "SubsysID", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                    originalValues.gpuInfo.subsysID = buffer;
                    AddLog("GPU SubsysID sauvegardé: " + originalValues.gpuInfo.subsysID);
                }

                
                bufferSize = sizeof(buffer);
                if (RegQueryValueExA(hKey, "HardwareID", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                    originalValues.gpuInfo.hardwareID = buffer;
                    AddLog("GPU HardwareID sauvegardé: " + originalValues.gpuInfo.hardwareID);
                }
            }

            RegCloseKey(hKey);
        }
    }

    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NVIDIA Corporation\\Global\\ClientPhysicalGPUs", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        WCHAR subKeyName[256];
        DWORD subKeyNameSize = 256;

        if (RegEnumKeyExW(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY subKey;
            std::wstring subKeyPath = L"SOFTWARE\\NVIDIA Corporation\\Global\\ClientPhysicalGPUs\\";
            subKeyPath += subKeyName;

            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKeyPath.c_str(), 0, KEY_READ, &subKey) == ERROR_SUCCESS) {
                WCHAR uuid[256] = { 0 };
                DWORD uuidSize = sizeof(uuid);

                if (RegQueryValueExW(subKey, L"GPUUIDBinary", NULL, NULL, (LPBYTE)uuid, &uuidSize) == ERROR_SUCCESS) {
                    originalValues.gpuInfo.uuid = std::string(uuid, uuid + wcslen(uuid));
                    AddLog("GPU UUID sauvegardé");
                }

                RegCloseKey(subKey);
            }
        }

        RegCloseKey(hKey);
    }
}


bool SpoofGPUID() {
    if (!IsUserAdmin()) {
        AddLog("L'utilisateur n'a pas les privilèges nécessaires pour modifier les identifiants GPU.");
        return false;
    }

    
    if (originalValues.gpuInfo.deviceID.empty()) {
        SaveOriginalGPUInfo();
    }

    AddLog("Spoofing des identifiants GPU...");

    HKEY hKey;
    std::vector<std::wstring> gpuPaths;

    
    gpuPaths.push_back(L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000");

    
    HKEY videoKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Video", 0, KEY_READ, &videoKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        WCHAR subKeyName[256];
        DWORD subKeyNameSize = 256;

        while (RegEnumKeyExW(videoKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            std::wstring videoPath = L"SYSTEM\\CurrentControlSet\\Control\\Video\\";
            videoPath += subKeyName;
            videoPath += L"\\0000";

            gpuPaths.push_back(videoPath);

            index++;
            subKeyNameSize = 256;
        }

        RegCloseKey(videoKey);
    }

    bool success = false;

    
    for (const auto& path : gpuPaths) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            
            std::string newDeviceID = GenerateRandomHWID(4);
            std::string newVendorID = "10DE";  
            std::string newSubsysID = GenerateRandomHWID(8);

            
            DWORD deviceIDSize = static_cast<DWORD>(newDeviceID.length() + 1);
            if (RegSetValueExA(hKey, "DeviceID", 0, REG_SZ, (BYTE*)newDeviceID.c_str(), deviceIDSize) == ERROR_SUCCESS) {
                AddLog("GPU DeviceID modifié: " + newDeviceID);
                success = true;
            }

            
            DWORD vendorIDSize = static_cast<DWORD>(newVendorID.length() + 1);
            if (RegSetValueExA(hKey, "VendorID", 0, REG_SZ, (BYTE*)newVendorID.c_str(), vendorIDSize) == ERROR_SUCCESS) {
                AddLog("GPU VendorID modifié: " + newVendorID);
                success = true;
            }

            
            DWORD subsysIDSize = static_cast<DWORD>(newSubsysID.length() + 1);
            if (RegSetValueExA(hKey, "SubsysID", 0, REG_SZ, (BYTE*)newSubsysID.c_str(), subsysIDSize) == ERROR_SUCCESS) {
                AddLog("GPU SubsysID modifié: " + newSubsysID);
                success = true;
            }

            
            std::string newHardwareID = "PCI\\" + newVendorID + "&" + newDeviceID + "&" + newSubsysID;
            DWORD hardwareIDSize = static_cast<DWORD>(newHardwareID.length() + 2);
            if (RegSetValueExA(hKey, "HardwareID", 0, REG_MULTI_SZ, (BYTE*)newHardwareID.c_str(), hardwareIDSize) == ERROR_SUCCESS) {
                AddLog("GPU HardwareID modifié: " + newHardwareID);
                success = true;
            }

            RegCloseKey(hKey);
        }
    }

    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NVIDIA Corporation\\Global\\ClientPhysicalGPUs", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        WCHAR subKeyName[256];
        DWORD subKeyNameSize = 256;

        if (RegEnumKeyExW(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY subKey;
            std::wstring subKeyPath = L"SOFTWARE\\NVIDIA Corporation\\Global\\ClientPhysicalGPUs\\";
            subKeyPath += subKeyName;

            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKeyPath.c_str(), 0, KEY_ALL_ACCESS, &subKey) == ERROR_SUCCESS) {
                std::string newUUID = GenerateWindowsGUID();
                std::wstring wNewUUID(newUUID.begin(), newUUID.end());

                DWORD uuidSize = static_cast<DWORD>(wNewUUID.length() + 1) * sizeof(WCHAR);
                if (RegSetValueExW(subKey, L"GPUUIDBinary", 0, REG_SZ, (LPBYTE)wNewUUID.c_str(), uuidSize) == ERROR_SUCCESS) {
                    AddLog("GPU UUID modifié: " + newUUID);
                    success = true;
                }

                RegCloseKey(subKey);
            }
        }

        RegCloseKey(hKey);
    }

    
    if (success) {
        AddLog("Tentative de réinitialisation du pilote GPU...");

        
        DISPLAY_DEVICEA displayDevice = { 0 }; 
        displayDevice.cb = sizeof(DISPLAY_DEVICEA);
        DWORD deviceIndex = 0;
        while (EnumDisplayDevices(NULL, deviceIndex, &displayDevice, 0)) {
            if (displayDevice.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) {
                DEVMODEA devMode = { 0 }; 
                devMode.dmSize = sizeof(DEVMODEA);
                devMode.dmDriverExtra = 0;
                devMode.dmDisplayFrequency = 0; 
                EnumDisplaySettings(displayDevice.DeviceName, ENUM_CURRENT_SETTINGS, &devMode);

                
                DWORD originalWidth = devMode.dmPelsWidth;
                devMode.dmPelsWidth = originalWidth - 1;
                ChangeDisplaySettings(&devMode, CDS_UPDATEREGISTRY);
                Sleep(1000);

                
                devMode.dmPelsWidth = originalWidth;
                ChangeDisplaySettings(&devMode, CDS_UPDATEREGISTRY);

                break;
            }
            deviceIndex++;
        }

        
        

        AddLog("Spoofing GPU terminé avec succès.");
        return true;
    }
    else {
        AddLog("Aucun identifiant GPU n'a pu être modifié.");
        return false;
    }
}


void SaveOriginalWindowsInfo() {
    HKEY hKey;

    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD bufferSize = sizeof(buffer);

        if (RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            originalValues.windowsInfo.machineGuid = buffer;
            AddLog("MachineGUID sauvegardé: " + originalValues.windowsInfo.machineGuid);
        }

        RegCloseKey(hKey);
    }

    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD bufferSize = sizeof(buffer);

        if (RegQueryValueExA(hKey, "ProductId", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            originalValues.windowsInfo.productID = buffer;
            AddLog("ProductID sauvegardé: " + originalValues.windowsInfo.productID);
        }

        
        DWORD installDate = 0;
        bufferSize = sizeof(installDate);
        if (RegQueryValueExA(hKey, "InstallDate", NULL, NULL, (LPBYTE)&installDate, &bufferSize) == ERROR_SUCCESS) {
            originalValues.windowsInfo.installDate = installDate;
            AddLog("InstallDate sauvegardé: " + std::to_string(originalValues.windowsInfo.installDate));
        }

        
        BYTE digitalProductId[256];
        bufferSize = sizeof(digitalProductId);
        if (RegQueryValueExA(hKey, "DigitalProductId", NULL, NULL, digitalProductId, &bufferSize) == ERROR_SUCCESS) {
            
            std::string hexId;
            for (DWORD i = 0; i < bufferSize; i++) {
                char hex[3];
                sprintf_s(hex, "%02X", digitalProductId[i]);
                hexId += hex;
            }
            originalValues.windowsInfo.digitalProductID = hexId;
            AddLog("DigitalProductID sauvegardé");
        }

        RegCloseKey(hKey);
    }

    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD bufferSize = sizeof(buffer);

        if (RegQueryValueExA(hKey, "HwProfileGuid", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            originalValues.windowsInfo.hwProfileGuid = buffer;
            AddLog("HwProfileGuid sauvegardé: " + originalValues.windowsInfo.hwProfileGuid);
        }

        RegCloseKey(hKey);
    }
}


bool SpoofWindowsIDs() {
    if (!IsUserAdmin()) {
        AddLog("L'utilisateur n'a pas les privilèges nécessaires pour modifier les identifiants Windows.");
        return false;
    }

    
    if (originalValues.windowsInfo.machineGuid.empty()) {
        SaveOriginalWindowsInfo();
    }

    AddLog("Spoofing des identifiants Windows...");
    bool success = false;

    
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        std::string newGuid = GenerateWindowsGUID();

        if (RegSetValueExA(hKey, "MachineGuid", 0, REG_SZ, (BYTE*)newGuid.c_str(), newGuid.length() + 1) == ERROR_SUCCESS) {
            AddLog("MachineGUID modifié: " + newGuid);
            success = true;
        }

        RegCloseKey(hKey);
    }

    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        
        std::string newProductID = GenerateRandomHWID(5, false) + "-OEM-" +
            GenerateRandomHWID(7, false) + "-" +
            GenerateRandomHWID(5, false);

        if (RegSetValueExA(hKey, "ProductId", 0, REG_SZ, (BYTE*)newProductID.c_str(), newProductID.length() + 1) == ERROR_SUCCESS) {
            AddLog("ProductID modifié: " + newProductID);
            success = true;
        }

        
        std::random_device rd;
        std::mt19937 gen(rd());
        
        std::uniform_int_distribution<> dis(1546300800, (DWORD)time(NULL));
        DWORD newInstallDate = dis(gen);

        if (RegSetValueExA(hKey, "InstallDate", 0, REG_DWORD, (BYTE*)&newInstallDate, sizeof(DWORD)) == ERROR_SUCCESS) {
            AddLog("InstallDate modifié: " + std::to_string(newInstallDate));
            success = true;
        }

        RegCloseKey(hKey);
    }

    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        std::string newGuid = GenerateWindowsGUID();

        if (RegSetValueExA(hKey, "HwProfileGuid", 0, REG_SZ, (BYTE*)newGuid.c_str(), newGuid.length() + 1) == ERROR_SUCCESS) {
            AddLog("HwProfileGuid modifié: " + newGuid);
            success = true;
        }

        RegCloseKey(hKey);
    }

    if (success) {
        AddLog("Spoofing des identifiants Windows terminé avec succès.");
        return true;
    }
    else {
        AddLog("Aucun identifiant Windows n'a pu être modifié.");
        return false;
    }
}


bool SpoofMachineGUID() {
    if (!IsUserAdmin()) {
        AddLog("L'utilisateur n'a pas les privilèges nécessaires pour modifier le MachineGUID.");
        return false;
    }

    
    if (originalValues.windowsInfo.machineGuid.empty()) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[256];
            DWORD bufferSize = sizeof(buffer);

            if (RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                originalValues.windowsInfo.machineGuid = buffer;
                AddLog("MachineGUID sauvegardé: " + originalValues.windowsInfo.machineGuid);
            }

            RegCloseKey(hKey);
        }
    }

    AddLog("Spoofing du MachineGUID...");

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        std::string newGuid = GenerateWindowsGUID();

        if (RegSetValueExA(hKey, "MachineGuid", 0, REG_SZ, (BYTE*)newGuid.c_str(), newGuid.length() + 1) == ERROR_SUCCESS) {
            AddLog("MachineGUID modifié: " + newGuid);
            RegCloseKey(hKey);
            return true;
        }

        RegCloseKey(hKey);
    }

    AddLog("Échec de la modification du MachineGUID.");
    return false;
}


bool SpoofVolumeID() {
    if (!IsUserAdmin()) {
        AddLog("L'utilisateur n'a pas les privilèges nécessaires pour modifier le Volume ID.");
        return false;
    }

    AddLog("Spoofing du Volume ID...");
    AddLog("Attention: Le spoofing du Volume ID est simulé dans cette version.");
    AddLog("Pour un vrai spoofing, un pilote en mode noyau ou un utilitaire comme 'VolumeID' est nécessaire.");

    
    
    

    
    std::string newVolumeID = GenerateRandomHWID(8);
    AddLog("Nouveau Volume ID (simulé): " + newVolumeID);

    
    AddLog("Simulation de commande: volumeid.exe C: " + newVolumeID);

    
    

    return true; 
}


bool SpoofAllIDs() {
    bool success = true;

    AddLog("=== Début du spoofing complet des identifiants ===");

    
    if (!SpoofSMBIOS()) {
        AddLog("⚠️ Échec du spoofing SMBIOS");
        success = false;
    }

    
    if (!SpoofDiskID()) {
        AddLog("⚠️ Échec du spoofing Disk ID");
        success = false;
    }

    
    if (!SpoofMAC()) {
        AddLog("⚠️ Échec du spoofing MAC");
        success = false;
    }

    
    if (!SpoofGPUID()) {
        AddLog("⚠️ Échec du spoofing GPU ID");
        success = false;
    }

    
    if (!SpoofWindowsIDs()) {
        AddLog("⚠️ Échec du spoofing Windows IDs");
        success = false;
    }

    
    if (!SpoofVolumeID()) {
        AddLog("⚠️ Échec du spoofing Volume ID");
        success = false;
    }

    if (success) {
        AddLog("✅ Spoofing complet terminé avec succès");
    }
    else {
        AddLog("⚠️ Spoofing complet terminé avec des erreurs");
    }

    return success;
}


bool RestoreSMBIOS();


bool RestoreAllValues() {
    bool success = true;

    AddLog("=== Début de la restauration des valeurs originales ===");

    
    if (!RestoreSMBIOS()) {
        AddLog("⚠️ Échec de la restauration SMBIOS");
        success = false;
    }

    
    for (const auto& macPair : originalValues.macAddresses) {
        const std::wstring& path = macPair.first;
        const std::wstring& mac = macPair.second;

        HKEY hSubKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_SET_VALUE, &hSubKey) == ERROR_SUCCESS) {
            if (!mac.empty()) {
                DWORD size = static_cast<DWORD>((mac.length() + 1) * sizeof(WCHAR));

                if (RegSetValueExW(hSubKey, L"NetworkAddress", 0, REG_SZ, (BYTE*)mac.c_str(), size) != ERROR_SUCCESS) {
                    AddLog("⚠️ Échec de la restauration d'une adresse MAC");
                    success = false;
                }
            }
            else {
                
                RegDeleteValueW(hSubKey, L"NetworkAddress");
            }

            RegCloseKey(hSubKey);

            
            WCHAR driverDesc[256] = { 0 };
            DWORD driverDescSize = sizeof(driverDesc);

            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                if (RegQueryValueExW(hSubKey, L"DriverDesc", NULL, NULL, (LPBYTE)driverDesc, &driverDescSize) == ERROR_SUCCESS) {
                    std::wstring disableCmd = L"netsh interface set interface \"";
                    disableCmd += driverDesc;
                    disableCmd += L"\" disabled";

                    std::wstring enableCmd = L"netsh interface set interface \"";
                    enableCmd += driverDesc;
                    enableCmd += L"\" enabled";

                    
                    STARTUPINFOW si = { sizeof(si) }; 
                    PROCESS_INFORMATION pi;
                    si.dwFlags = STARTF_USESHOWWINDOW;
                    si.wShowWindow = SW_HIDE;

                    
                    if (CreateProcessW(NULL, (LPWSTR)disableCmd.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                        WaitForSingleObject(pi.hProcess, 5000);
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                        Sleep(1000);

                        
                        if (CreateProcessW(NULL, (LPWSTR)enableCmd.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                            WaitForSingleObject(pi.hProcess, 5000);
                            CloseHandle(pi.hProcess);
                            CloseHandle(pi.hThread);
                        }
                    }
                }
                RegCloseKey(hSubKey);
            }
        }
    }

    
    if (!originalValues.gpuInfo.deviceID.empty()) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {

            DWORD deviceIDSize = static_cast<DWORD>(originalValues.gpuInfo.deviceID.length() + 1);
            DWORD vendorIDSize = static_cast<DWORD>(originalValues.gpuInfo.vendorID.length() + 1);
            DWORD subsysIDSize = static_cast<DWORD>(originalValues.gpuInfo.subsysID.length() + 1);
            DWORD hardwareIDSize = static_cast<DWORD>(originalValues.gpuInfo.hardwareID.length() + 2);

            if (RegSetValueExA(hKey, "DeviceID", 0, REG_SZ, (BYTE*)originalValues.gpuInfo.deviceID.c_str(), deviceIDSize) != ERROR_SUCCESS) {
                AddLog("⚠️ Échec de la restauration du DeviceID GPU");
                success = false;
            }

            if (RegSetValueExA(hKey, "VendorID", 0, REG_SZ, (BYTE*)originalValues.gpuInfo.vendorID.c_str(), vendorIDSize) != ERROR_SUCCESS) {
                AddLog("⚠️ Échec de la restauration du VendorID GPU");
                success = false;
            }

            if (RegSetValueExA(hKey, "SubsysID", 0, REG_SZ, (BYTE*)originalValues.gpuInfo.subsysID.c_str(), subsysIDSize) != ERROR_SUCCESS) {
                AddLog("⚠️ Échec de la restauration du SubsysID GPU");
                success = false;
            }

            if (RegSetValueExA(hKey, "HardwareID", 0, REG_MULTI_SZ, (BYTE*)originalValues.gpuInfo.hardwareID.c_str(), hardwareIDSize) != ERROR_SUCCESS) {
                AddLog("⚠️ Échec de la restauration du HardwareID GPU");
                success = false;
            }

            RegCloseKey(hKey);
        }
    }

    
    if (!originalValues.windowsInfo.machineGuid.empty()) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            DWORD guidSize = static_cast<DWORD>(originalValues.windowsInfo.machineGuid.length() + 1);

            if (RegSetValueExA(hKey, "MachineGuid", 0, REG_SZ, (BYTE*)originalValues.windowsInfo.machineGuid.c_str(), guidSize) != ERROR_SUCCESS) {
                AddLog("⚠️ Échec de la restauration du MachineGUID");
                success = false;
            }

            RegCloseKey(hKey);
        }
    }

    if (!originalValues.windowsInfo.productID.empty()) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            DWORD productIDSize = static_cast<DWORD>(originalValues.windowsInfo.productID.length() + 1);

            if (RegSetValueExA(hKey, "ProductId", 0, REG_SZ, (BYTE*)originalValues.windowsInfo.productID.c_str(), productIDSize) != ERROR_SUCCESS) {
                AddLog("⚠️ Échec de la restauration du ProductID");
                success = false;
            }

            if (RegSetValueExA(hKey, "InstallDate", 0, REG_DWORD, (BYTE*)&originalValues.windowsInfo.installDate, sizeof(DWORD)) != ERROR_SUCCESS) {
                AddLog("⚠️ Échec de la restauration de l'InstallDate");
                success = false;
            }

            RegCloseKey(hKey);
        }
    }

    if (!originalValues.windowsInfo.hwProfileGuid.empty()) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            DWORD guidSize = static_cast<DWORD>(originalValues.windowsInfo.hwProfileGuid.length() + 1);

            if (RegSetValueExA(hKey, "HwProfileGuid", 0, REG_SZ, (BYTE*)originalValues.windowsInfo.hwProfileGuid.c_str(), guidSize) != ERROR_SUCCESS) {
                AddLog("⚠️ Échec de la restauration du HwProfileGuid");
                success = false;
            }

            RegCloseKey(hKey);
        }
    }

    if (success) {
        AddLog("✅ Restauration complète terminée avec succès");
    }
    else {
        AddLog("⚠️ Restauration complète terminée avec des erreurs");
    }

    return success;
}


bool RestoreSMBIOS() {
    if (originalValues.smbiosSerial.empty()) {
        AddLog("Aucune valeur SMBIOS originale à restaurer");
        return true;
    }

    AddLog("Restauration des valeurs SMBIOS originales...");

    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        AddLog("Erreur lors de l'initialisation COM: " + std::to_string(hres));
        return false;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (SUCCEEDED(hres)) {
        IWbemServices* pSvc = NULL;
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);

        if (SUCCEEDED(hres)) {
            
            hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

            if (FAILED(hres)) {
                AddLog("Erreur lors de la configuration de la sécurité WMI: " + std::to_string(hres));
                pSvc->Release();
                pLoc->Release();
                CoUninitialize();
                return false;
            }

            IEnumWbemClassObject* pEnumerator = NULL;
            hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_BIOS"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

            if (SUCCEEDED(hres)) {
                IWbemClassObject* pclsObj = NULL;
                ULONG uReturn = 0;

                while (pEnumerator) {
                    hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                    if (0 == uReturn) break;

                    
                    _variant_t varSerial(originalValues.smbiosSerial.c_str());
                    pclsObj->Put(L"SerialNumber", 0, &varSerial, 0);

                    
                    if (!originalValues.smbiosManufacturer.empty()) {
                        _variant_t varManufacturer(originalValues.smbiosManufacturer.c_str());
                        pclsObj->Put(L"Manufacturer", 0, &varManufacturer, 0);
                    }

                    
                    if (!originalValues.smbiosProduct.empty()) {
                        _variant_t varProduct(originalValues.smbiosProduct.c_str());
                        pclsObj->Put(L"Name", 0, &varProduct, 0);
                    }

                    
                    if (!originalValues.smbiosVersion.empty()) {
                        _variant_t varVersion(originalValues.smbiosVersion.c_str());
                        pclsObj->Put(L"Version", 0, &varVersion, 0);
                    }

                    
                    hres = pSvc->PutInstance(pclsObj, WBEM_FLAG_UPDATE_ONLY, NULL, NULL);
                    if (SUCCEEDED(hres)) {
                        AddLog("Valeurs SMBIOS restaurées avec succès");
                    }
                    else {
                        AddLog("Erreur lors de la mise à jour de l'instance BIOS: " + std::to_string(hres));
                    }

                    pclsObj->Release();
                }

                pEnumerator->Release();
            }
            else {
                AddLog("Erreur lors de l'exécution de la requête WMI: " + std::to_string(hres));
            }

            pSvc->Release();
        }
        else {
            AddLog("Erreur lors de la connexion au serveur WMI: " + std::to_string(hres));
        }

        pLoc->Release();
    }
    else {
        AddLog("Erreur lors de la création de l'instance WbemLocator: " + std::to_string(hres));
    }

    CoUninitialize();
    return SUCCEEDED(hres);
}


class AutoRestoreScheduler {
private:
    bool scheduled;
    std::thread schedulerThread;
    std::mutex schedulerMutex;
    bool stopRequested;
    int minutesDelay;

public:
    AutoRestoreScheduler() : scheduled(false), stopRequested(false), minutesDelay(60) {}

    ~AutoRestoreScheduler() {
        StopScheduler();
    }

    bool IsScheduled() const {
        return scheduled;
    }

    int GetDelayMinutes() const {
        return minutesDelay;
    }

    void SetDelayMinutes(int minutes) {
        if (minutes < 1) minutes = 1;
        minutesDelay = minutes;
    }

    bool ScheduleRestore(int minutes) {
        std::lock_guard<std::mutex> lock(schedulerMutex);

        if (scheduled) {
            StopScheduler();
        }

        minutesDelay = minutes;
        stopRequested = false;

        
        schedulerThread = std::thread([this]() {
            AddLog("Restauration automatique programmée dans " + std::to_string(minutesDelay) + " minutes");

            for (int i = 0; i < minutesDelay; i++) {
                
                for (int j = 0; j < 60; j++) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));

                    std::lock_guard<std::mutex> checkLock(schedulerMutex);
                    if (stopRequested) {
                        AddLog("Restauration automatique annulée");
                        scheduled = false;
                        return;
                    }
                }

                
                int remaining = minutesDelay - i - 1;
                if (remaining % 5 == 0 || remaining <= 5) {
                    AddLog("Restauration automatique dans " + std::to_string(remaining) + " minutes");
                }
            }

            
            AddLog("Exécution de la restauration automatique...");
            RestoreAllValues();

            std::lock_guard<std::mutex> finalLock(schedulerMutex);
            scheduled = false;
            });

        schedulerThread.detach();
        scheduled = true;
        return true;
    }

    void StopScheduler() {
        std::lock_guard<std::mutex> lock(schedulerMutex);

        if (scheduled) {
            stopRequested = true;
            
        }
    }
};


AutoRestoreScheduler g_AutoRestoreScheduler;


void RenderAdvancedUI() {
    static bool antiCheatProtectionEnabled = false;
    static bool memoryProtectionEnabled = false;
    static bool autoRestoreEnabled = false;
    static int autoRestoreDelay = 60;
    static AntiCheatProtection antiCheatProtection;
    static MemoryProtection memoryProtection;
    static bool showHelpTips = true;
    static int currentTab = 0;
    static char backupPassword[32] = "password";

    
    static bool antiCheatDetected = false;
    static bool antiCheatChecked = false;

    if (!antiCheatChecked) {
        antiCheatDetected = antiCheatProtection.DetectAntiCheat();
        antiCheatChecked = true;
    }

    ImGui::SetNextWindowSize(ImVec2(800, 600), ImGuiCond_FirstUseEver);
    ImGui::Begin("HWID Spoofer Pro", nullptr);

    
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "Version %s", SPOOFER_VERSION);
    ImGui::SameLine();

    if (IsUserAdmin()) {
        ImGui::TextColored(ImVec4(0.0f, 0.8f, 0.0f, 1.0f), "Privilèges Admin: Oui");
    }
    else {
        ImGui::TextColored(ImVec4(0.8f, 0.0f, 0.0f, 1.0f), "Privilèges Admin: Non");
        ImGui::SameLine();
        if (ImGui::Button("Élever les privilèges")) {
            ElevatePrivileges();
        }
    }

    
    if (antiCheatDetected) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
        ImGui::TextWrapped("⚠️ AVERTISSEMENT: Systèmes anti-cheat détectés! Des protections additionnelles sont recommandées.");
        ImGui::PopStyleColor();
    }

    
    ImGui::Separator();
    if (ImGui::BeginTabBar("MainTabs")) {
        if (ImGui::BeginTabItem("Spoofer")) {
            currentTab = 0;
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Protection")) {
            currentTab = 1;
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Restauration")) {
            currentTab = 2;
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Options")) {
            currentTab = 3;
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("À propos")) {
            currentTab = 4;
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::Separator();

    
    switch (currentTab) {
    case 0: 
    {
        
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.4f, 0.8f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.0f, 0.5f, 0.9f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.0f, 0.6f, 1.0f, 1.0f));

        if (ImGui::Button("SPOOFER TOUS LES IDENTIFIANTS", ImVec2(-1, 50))) {
            SpoofAllIDs();
        }

        ImGui::PopStyleColor(3);

        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Modifie tous les identifiants hardware en une seule opération");
        }

        ImGui::Separator();

        
        ImGui::Columns(2, "spoofing_columns", true);

        if (ImGui::Button("Spoofer SMBIOS", ImVec2(-1, 0))) {
            SpoofSMBIOS();
        }
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Modifie les identifiants du BIOS du système");
        }

        if (ImGui::Button("Spoofer Disque ID", ImVec2(-1, 0))) {
            SpoofDiskID();
        }
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Modifie les numéros de série des disques");
        }

        if (ImGui::Button("Spoofer MAC Address", ImVec2(-1, 0))) {
            SpoofMAC();
        }
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Modifie les adresses MAC des cartes réseau");
        }

        ImGui::NextColumn();

        if (ImGui::Button("Spoofer GPU ID", ImVec2(-1, 0))) {
            SpoofGPUID();
        }
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Modifie les identifiants des cartes graphiques");
        }

        if (ImGui::Button("Spoofer Windows ID", ImVec2(-1, 0))) {
            SpoofWindowsIDs();
        }
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Modifie les identifiants du système Windows");
        }

        if (ImGui::Button("Spoofer MachineGUID", ImVec2(-1, 0))) {
            SpoofMachineGUID();
        }
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Modifie uniquement le GUID de la machine");
        }

        ImGui::Columns(1);

        
        ImGui::Separator();
        if (ImGui::CollapsingHeader("Options avancées", ImGuiTreeNodeFlags_DefaultOpen)) {
            if (ImGui::Button("Spoofer Volume ID", ImVec2(-1, 0))) {
                SpoofVolumeID();
            }
            if (showHelpTips && ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Modifie l'identificateur du volume système (simulation)");
            }
        }
    }
    break;

    case 1: 
    {
        ImGui::TextWrapped("Configurez les protections pour réduire les risques de détection par les anti-cheats");
        ImGui::Separator();

        
        if (ImGui::Checkbox("Activer la protection anti-cheat", &antiCheatProtectionEnabled)) {
            if (antiCheatProtectionEnabled) {
                antiCheatProtection.ApplyProtections();
                AddLog("Protections anti-cheat activées");
            }
            else {
                AddLog("Protections anti-cheat désactivées");
            }
        }
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Implémente des techniques pour éviter la détection par les anti-cheats");
        }

        
        if (ImGui::Checkbox("Activer la protection mémoire", &memoryProtectionEnabled)) {
            if (memoryProtectionEnabled) {
                
                
                
                memoryProtection.ProtectMemoryRegion((void*)&originalValues.smbiosSerial, 4096);
                memoryProtection.ProtectMemoryRegion((void*)&originalValues.macAddresses, 4096);
                memoryProtection.ProtectMemoryRegion((void*)&originalValues.windowsInfo, 4096);
                AddLog("Protections mémoire activées");
            }
            else {
                memoryProtection.RestoreProtections();
                AddLog("Protections mémoire désactivées");
            }
        }
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Protège les régions mémoire sensibles contre l'analyse");
        }

        
        ImGui::Separator();
        if (ImGui::Button("Analyser les anti-cheats", ImVec2(-1, 30))) {
            antiCheatDetected = antiCheatProtection.DetectAntiCheat();
            if (!antiCheatDetected) {
                AddLog("Aucun système anti-cheat détecté");
            }
        }
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Vérifie la présence de systèmes anti-cheat connus");
        }

        
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.0f, 1.0f), "Statistiques de protection:");

        if (antiCheatDetected) {
            ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "• Système anti-cheat détecté");
        }
        else {
            ImGui::TextColored(ImVec4(0.0f, 0.8f, 0.0f, 1.0f), "• Aucun système anti-cheat détecté");
        }

        ImGui::TextColored(antiCheatProtectionEnabled ? ImVec4(0.0f, 0.8f, 0.0f, 1.0f) : ImVec4(0.8f, 0.0f, 0.0f, 1.0f),
            "• Protection anti-cheat: %s", antiCheatProtectionEnabled ? "Activée" : "Désactivée");

        ImGui::TextColored(memoryProtectionEnabled ? ImVec4(0.0f, 0.8f, 0.0f, 1.0f) : ImVec4(0.8f, 0.0f, 0.0f, 1.0f),
            "• Protection mémoire: %s", memoryProtectionEnabled ? "Activée" : "Désactivée");
    }
    break;

    case 2: 
    {
        ImGui::TextWrapped("Gérez la restauration des identifiants d'origine");
        ImGui::Separator();

        
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.4f, 0.4f, 1.0f));

        if (ImGui::Button("RESTAURER TOUTES LES VALEURS ORIGINALES", ImVec2(-1, 50))) {
            RestoreAllValues();
        }

        ImGui::PopStyleColor(3);
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Restaure tous les identifiants à leurs valeurs d'origine");
        }

        ImGui::Separator();

        
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.0f, 1.0f), "Restauration automatique:");

        if (ImGui::Checkbox("Activer la restauration automatique", &autoRestoreEnabled)) {
            if (autoRestoreEnabled) {
                g_AutoRestoreScheduler.ScheduleRestore(autoRestoreDelay);
            }
            else {
                g_AutoRestoreScheduler.StopScheduler();
            }
        }
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Restaure automatiquement les valeurs originales après un délai");
        }

        if (autoRestoreEnabled) {
            if (ImGui::SliderInt("Délai de restauration (minutes)", &autoRestoreDelay, 1, 120)) {
                g_AutoRestoreScheduler.StopScheduler();
                g_AutoRestoreScheduler.ScheduleRestore(autoRestoreDelay);
            }

            
            if (ImGui::Button("Annuler la restauration programmée")) {
                g_AutoRestoreScheduler.StopScheduler();
                autoRestoreEnabled = false;
            }
        }

        
        if (g_AutoRestoreScheduler.IsScheduled()) {
            ImGui::TextColored(ImVec4(0.0f, 0.8f, 0.0f, 1.0f),
                "Restauration programmée dans %d minutes",
                g_AutoRestoreScheduler.GetDelayMinutes());
        }

        
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.0f, 1.0f), "Sauvegarde et chargement:");

        ImGui::InputText("Mot de passe de sauvegarde", backupPassword, sizeof(backupPassword), ImGuiInputTextFlags_Password);

        if (ImGui::Button("Sauvegarder les valeurs originales", ImVec2(0, 0))) {
            if (originalValues.SaveToFile(BACKUP_FILENAME, backupPassword)) {
                AddLog("Valeurs originales sauvegardées dans " + std::string(BACKUP_FILENAME));
            }
            else {
                AddLog("Erreur lors de la sauvegarde des valeurs originales");
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Charger les valeurs originales", ImVec2(0, 0))) {
            if (originalValues.LoadFromFile(BACKUP_FILENAME, backupPassword)) {
                AddLog("Valeurs originales chargées depuis " + std::string(BACKUP_FILENAME));
            }
            else {
                AddLog("Erreur lors du chargement des valeurs originales");
            }
        }
    }
    break;

    case 3: 
    {
        ImGui::TextWrapped("Configuration du spoofer");
        ImGui::Separator();

        
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.0f, 1.0f), "Options d'interface:");

        ImGui::Checkbox("Afficher les infobulles d'aide", &showHelpTips);
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Active/désactive les infobulles qui apparaissent au survol");
        }

        
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.0f, 1.0f), "Options de journalisation:");

        static bool fileLogging = false;
        if (ImGui::Checkbox("Activer la journalisation dans un fichier", &fileLogging)) {
            g_Logger.EnableFileLogging(fileLogging);
            if (fileLogging) {
                AddLog("Journalisation dans un fichier activée");
            }
            else {
                AddLog("Journalisation dans un fichier désactivée");
            }
        }
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Enregistre les logs dans un fichier externe");
        }

        static char logFilePath[256] = "spoofer_log.txt";
        if (fileLogging) {
            ImGui::InputText("Chemin du fichier de log", logFilePath, sizeof(logFilePath));
            if (ImGui::Button("Appliquer")) {
                g_Logger.EnableFileLogging(true, logFilePath);
                AddLog("Chemin du fichier de log modifié: " + std::string(logFilePath));
            }
        }

        
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.0f, 1.0f), "Options de démarrage:");

        static bool startWithWindows = false;
        if (ImGui::Checkbox("Démarrer avec Windows", &startWithWindows)) {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"AUTO_RESTORE_KEY", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                if (startWithWindows) {
                    
                    char exePath[MAX_PATH];
                    GetModuleFileNameA(NULL, exePath, MAX_PATH);

                    
                    RegSetValueExA(hKey, "HWIDSpoofer", 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1);
                    AddLog("Application ajoutée au démarrage de Windows");
                }
                else {
                    
                    RegDeleteValueA(hKey, "HWIDSpoofer");
                    AddLog("Application supprimée du démarrage de Windows");
                }

                RegCloseKey(hKey);
            }
        }
        if (showHelpTips && ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Lance automatiquement l'application au démarrage de Windows");
        }

        
        if (!startWithWindows) {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"AUTO_RESTORE_KEY", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                char value[MAX_PATH] = { 0 };
                DWORD valueSize = sizeof(value);

                if (RegQueryValueExA(hKey, "HWIDSpoofer", NULL, NULL, (BYTE*)value, &valueSize) == ERROR_SUCCESS) {
                    startWithWindows = true;
                }

                RegCloseKey(hKey);
            }
        }
    }
    break;

    case 4: 
    {
        ImGui::TextColored(ImVec4(0.0f, 0.8f, 0.8f, 1.0f), "HWID Spoofer Pro v%s", SPOOFER_VERSION);
        ImGui::Separator();

        ImGui::TextWrapped(
            "Ce logiciel est conçu pour modifier les identifiants matériels de votre système. "
            "Il est destiné à des fins éducatives et de protection de la vie privée uniquement."
        );

        ImGui::Spacing();
        ImGui::TextWrapped(
            "AVERTISSEMENT: L'utilisation de ce logiciel pour contourner les mesures de sécurité "
            "des jeux ou logiciels peut violer leurs conditions d'utilisation et entraîner "
            "la suspension ou la suppression de votre compte."
        );

        ImGui::Spacing();
        ImGui::TextWrapped(
            "Fonctionnalités:"
        );

        ImGui::BulletText("Modification des identifiants SMBIOS (BIOS, Serial, etc.)");
        ImGui::BulletText("Spoofing des numéros de série des disques");
        ImGui::BulletText("Modification des adresses MAC des cartes réseau");
        ImGui::BulletText("Spoofing des identifiants GPU");
        ImGui::BulletText("Modification des identifiants Windows (MachineGUID, etc.)");
        ImGui::BulletText("Protections contre les anti-cheats");
        ImGui::BulletText("Restauration automatique programmée");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextWrapped("Développé par: L'équipe SpoofMaster");
    }
    break;
    }

    
    ImGui::Separator();
    DisplayLogs();

    ImGui::End();
}


int APIENTRY WinMain(HINSTANCE , HINSTANCE , LPSTR lpCmdLine, int nCmdShow) {
    
    g_Logger.EnableFileLogging(false);
    AddLog("HWID Spoofer Pro v" SPOOFER_VERSION " démarré");

    
    if (!IsUserAdmin()) {
        AddLog("Attention: L'application ne dispose pas des privilèges administrateur");
        AddLog("Certaines fonctionnalités ne seront pas disponibles");

        
        if (MessageBoxW(NULL,
            L"Cette application nécessite des privilèges administrateur pour fonctionner correctement.\n\nVoulez-vous redémarrer avec des privilèges élevés?",
            L"HWID Spoofer - Élévation des privilèges",
            MB_YESNO | MB_ICONQUESTION) == IDYES) {
            ElevatePrivileges();
            return 0;
        }
    }

    
    AntiCheatProtection antiCheatProtection;
    if (antiCheatProtection.DetectAntiCheat()) {
        AddLog("⚠️ AVERTISSEMENT: Des systèmes anti-cheat ont été détectés sur ce système");
        AddLog("Des protections supplémentaires sont recommandées");
    }

    
    SaveOriginalSMBIOS();
    SaveOriginalDiskInfo();
    SaveOriginalMAC();
    SaveOriginalGPUInfo();
    SaveOriginalWindowsInfo();

    
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, _T("HWID Spoofer"), NULL };
    RegisterClassEx(&wc);
    HWND hwnd = CreateWindow(wc.lpszClassName, _T("HWID Spoofer Pro"), WS_OVERLAPPEDWINDOW, 100, 100, 800, 600, NULL, NULL, wc.hInstance, NULL);

    
    if (CreateDeviceD3D(hwnd) != true) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
    SetModernTheme();

    
    bool done = false;

    
    while (!done) {
        
        MSG msg;
        while (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        
        RenderAdvancedUI();

        
        ImGui::Render();
        if (!g_mainRenderTargetView) {
            AddLog("Erreur : g_mainRenderTargetView n'est pas initialisé.");
            return 0;
        }
        ImVec4 clearColor(0.10f, 0.10f, 0.10f, 1.00f);
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, (float*)&clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}