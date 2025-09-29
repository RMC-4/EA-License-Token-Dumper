// <#
//     EA Denuvo Token Dumper
//     Copyright (C) 2025 RMC
//     Licensed under the Community Use License (CUL-1.0)
//     See: https://github.com/RMC-4/EA-License-Token-Dumper/blob/main/LICENSE
// #>


#include <windows.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <regex>
#include <string>
#include <iostream>
#include <filesystem>

// Crypto++
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

// TinyXML2
#include "tinyxml2.h"

namespace fs = std::filesystem;

static std::wstring markerPath = fs::temp_directory_path() / L"showcase_token_dumper_marker.flag";

static void ShowMessage(const std::wstring &text, const std::wstring &title, UINT icon)
{
    MessageBoxW(nullptr, text.c_str(), title.c_str(), MB_OK | icon);
}

static std::string ReadFileBytes(const std::wstring &path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

static bool WriteFileText(const std::wstring &path, const std::string &text)
{
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write(text.data(), text.size());
    return true;
}

static std::string TryDecrypt(const std::string &input, const byte key[16], const byte iv[16])
{
    try {
        std::string decrypted;
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(key, 16, iv);
        CryptoPP::StringSource ss(input, true,
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(decrypted),
                CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING
            )
        );
        return decrypted;
    }
    catch (...) {
        return {};
    }
}

static bool MarkerExists()
{
    return fs::exists(markerPath);
}

static void CreateMarker()
{
    std::ofstream file(markerPath);
    file << "1";
    file.close();
}

static void RemoveMarker()
{
    if (fs::exists(markerPath))
        fs::remove(markerPath);
}

static void RelaunchApp()
{
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) return;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    // Relaunch the app normally (no DLL injection)
    if (CreateProcessW(exePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    ExitProcess(0); // Terminate current process to avoid duplicate running
}

extern "C" __declspec(dllexport) void Run(bool overwrite = true)
{
    try
    {
        if (MarkerExists())
        {
            // DLL logic already run for this app execution, do nothing
            RemoveMarker();
            return;
        }

        std::wstring dlfPath = L"C:\\ProgramData\\Electronic Arts\\EA Services\\License\\16425677_sc.dlf";
        std::wstring cfgPath = fs::current_path().wstring() + L"\\anadius.cfg";

        if (!fs::exists(dlfPath)) {
            ShowMessage(L"License file not found:\n" + dlfPath, L"Error", MB_ICONERROR);
            return;
        }

        if (overwrite && !fs::exists(cfgPath)) {
            ShowMessage(L"Config file not found:\n" + cfgPath, L"Error", MB_ICONERROR);
            return;
        }

        byte key[16] = { 65,50,114,45,208,130,239,176,220,100,87,197,118,104,202,9 };
        byte iv[16] = { 0 };

        std::string fileBytes = ReadFileBytes(dlfPath);
        if (fileBytes.empty()) {
            ShowMessage(L"Failed to read license file.", L"Error", MB_ICONERROR);
            return;
        }

        std::string decrypted = TryDecrypt(fileBytes, key, iv);
        if (decrypted.empty()) {
            if (fileBytes.size() <= 0x41) {
                ShowMessage(L"File too small for fallback decryption.", L"Error", MB_ICONERROR);
                return;
            }
            std::string slice = fileBytes.substr(0x41);
            decrypted = TryDecrypt(slice, key, iv);
        }

        if (decrypted.empty()) {
            ShowMessage(L"Decryption failed. Invalid/corrupt license file.", L"Error", MB_ICONERROR);
            return;
        }

        tinyxml2::XMLDocument doc;
        if (doc.Parse(decrypted.c_str()) != tinyxml2::XML_SUCCESS) {
            ShowMessage(L"Decrypted data is not valid XML.", L"Error", MB_ICONERROR);
            return;
        }

        tinyxml2::XMLElement* root = doc.RootElement();
        if (!root) {
            ShowMessage(L"No XML root found.", L"Error", MB_ICONERROR);
            return;
        }

        tinyxml2::XMLElement* tokenNode = root->FirstChildElement("GameToken");
        if (!tokenNode) {
            ShowMessage(L"GameToken not found in license.", L"Error", MB_ICONERROR);
            return;
        }

        std::string token = tokenNode->GetText() ? tokenNode->GetText() : "";
        token = std::regex_replace(token, std::regex("\\s+"), "");

     if (overwrite) {
        std::wstring backupPath = cfgPath + L".bak";
        fs::copy_file(cfgPath, backupPath, fs::copy_options::overwrite_existing);

        std::ifstream in(cfgPath);
        std::ostringstream buffer;
        buffer << in.rdbuf();
        std::string configText = buffer.str();

        std::regex pattern(R"((\"DenuvoToken\"\s+\".*?\"))");
        std::string replacement = "\"DenuvoToken\"           \"" + token + "\"";

        if (std::regex_search(configText, pattern)) {
            // Replace the existing DenuvoToken line
            std::string updated = std::regex_replace(configText, pattern, replacement);

            if (!WriteFileText(cfgPath, updated)) {
                ShowMessage(L"Failed to update config.", L"Error", MB_ICONERROR);
                return;
            }

            // (Optional) Commented out success popup to suppress it
            // ShowMessage(L"DenuvoToken updated!\nBackup created at:\n" + backupPath, L"Success", MB_ICONINFORMATION);
        }
        else {
            // DenuvoToken not found, do not append or change config
            ShowMessage(L"DenuvoToken entry not found in config. No changes made.", L"Info", MB_ICONINFORMATION);
        }

        // Delete all Denuvo_ticket_*.txt files in the config folder
        try {
            fs::path configDir = fs::path(cfgPath).parent_path();
            for (const auto& entry : fs::directory_iterator(configDir)) {
                if (entry.is_regular_file()) {
                    const auto& filename = entry.path().filename().wstring();
                    if (filename.substr(0, 13) == L"Denuvo_ticket_"
                        && filename.substr(filename.size() - 4) == L".txt") {
                        fs::remove(entry.path());
                    }
                }
            }
        }
        catch (const std::exception&) {
            ShowMessage(L"Failed to delete some ticket files.", L"Warning", MB_ICONWARNING);
        }
    }
    else {
        ShowMessage(L"DenuvoToken extracted successfully!", L"Success", MB_ICONINFORMATION);
    }


        CreateMarker();

        // After DLL logic, relaunch app without DLL injection
        RelaunchApp();
    }
    catch (const std::exception& ex)
    {
        MessageBoxA(nullptr, ex.what(), "DLL Error", MB_OK | MB_ICONERROR);
        // Do not terminate app; continue normal launch
    }
    catch (...)
    {
        MessageBoxA(nullptr, "Unknown DLL Error", "DLL Error", MB_OK | MB_ICONERROR);
        // Do not terminate app; continue normal launch
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        Run(true);
        break;
    case DLL_PROCESS_DETACH:
        RemoveMarker(); // Remove marker on process exit to allow future DLL runs
        break;
    }
    return TRUE;
}