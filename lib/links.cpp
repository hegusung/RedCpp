/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "links.h"

Links::Links()
{
}

Links::~Links()
{
}

std::list<Link>* Links::list_links(std::string path, bool recursive)
{
    std::list<Link>* link_list = new std::list<Link>();

    if (path.back() != '\\')
    {
        path = path + "\\";
    }

    this->list_links_in_subdir(path, link_list, recursive);
 
    return link_list;
}

void Links::list_links_in_subdir(std::string path, std::list<Link>* link_list, bool recursive)
{
    WIN32_FIND_DATA data;
    HANDLE hFind = FindFirstFile((path + "*").c_str(), &data);      // FILES

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::string filename = std::string(data.cFileName);

            if (recursive && (filename.compare(".") != 0) && (filename.compare("..") != 0) && ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0))
            {
                this->list_links_in_subdir(path + filename + "\\", link_list, recursive);
            }

            if (filename.substr(filename.find_last_of(".") + 1) == "lnk") 
            {
                this->get_link_info((path + filename).c_str(), link_list);
            }

        } while (FindNextFile(hFind, &data));
        FindClose(hFind);
    }
}

void Links::get_link_info(std::string path, std::list<Link>* link_list)
{
    HRESULT hres;
    IShellLinkW* psl;
    WCHAR szGotPath[MAX_PATH];
    WCHAR szDescription[MAX_PATH];
    WIN32_FIND_DATAW wfd;

    bool success = com.CreateInstance(CLSID_ShellLink, IID_IShellLink, (LPVOID*)&psl, NULL, NULL, NULL, NULL);
    if (!success)
        return;

    IPersistFile* ppf;
    // Get a pointer to the IPersistFile interface. 
    hres = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);

    if (SUCCEEDED(hres))
    {
        WCHAR wsz[MAX_PATH];

        // Ensure that the string is Unicode. 
        MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wsz, MAX_PATH);

        // Add code here to check return value from MultiByteWideChar 
        // for success.

        // Load the shortcut. 
        hres = ppf->Load(wsz, STGM_READ);

        if (SUCCEEDED(hres))
        {
            std::string lnk_path = "";
            std::string lnk_args = "";
            std::string lnk_description = "";

            // Get the path to the link target. 
            hres = psl->GetPath(szGotPath, MAX_PATH, &wfd, SLGP_RAWPATH);
            if (SUCCEEDED(hres))
            {
                lnk_path = std::string((char*)szGotPath);
            }

            // Get the description of the target. 
            hres = psl->GetDescription(szDescription, MAX_PATH);
            if (SUCCEEDED(hres))
            {
                lnk_description = std::string((char*)szDescription);
            }

            // Get the path to the link target. 
            hres = psl->GetArguments(szGotPath, MAX_PATH);
            if (SUCCEEDED(hres))
            {
                lnk_args = std::string((char*)szGotPath);
            }

            link_list->push_back(Link(path.c_str(), lnk_description.c_str(), lnk_path.c_str(), lnk_args.c_str()));
        }

        // Release the pointer to the IPersistFile interface. 
        ppf->Release();
    }

    // Release the pointer to the IShellLink interface. 
    psl->Release();

    /*
    //  ------------------------------------------------------
 //  Initialize COM.
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("CoInitializeEx failed: %x\n", hr);
#endif
        return;
    }

    // Get a pointer to the IShellLink interface. It is assumed that CoInitialize
    // has already been called. 
    hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
    if (SUCCEEDED(hres))
    {
        IPersistFile* ppf;

        // Get a pointer to the IPersistFile interface. 
        hres = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);

        if (SUCCEEDED(hres))
        {
            WCHAR wsz[MAX_PATH];

            // Ensure that the string is Unicode. 
            MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wsz, MAX_PATH);

            // Add code here to check return value from MultiByteWideChar 
            // for success.

            // Load the shortcut. 
            hres = ppf->Load(wsz, STGM_READ);

            if (SUCCEEDED(hres))
            {
                std::string lnk_path = "";
                std::string lnk_args = "";
                std::string lnk_description = "";

                // Get the path to the link target. 
                hres = psl->GetPath(szGotPath, MAX_PATH, &wfd, SLGP_RAWPATH);
                if (SUCCEEDED(hres))
                {
                    lnk_path = std::string((char*)szGotPath);
                }

                // Get the description of the target. 
                hres = psl->GetDescription(szDescription, MAX_PATH);
                if (SUCCEEDED(hres))
                {
                    lnk_description = std::string((char*)szDescription);
                }

                // Get the path to the link target. 
                hres = psl->GetArguments(szGotPath, MAX_PATH);
                if (SUCCEEDED(hres))
                {
                    lnk_args = std::string((char*)szGotPath);
                }

                link_list->push_back(Link(path.c_str(), lnk_description.c_str(), lnk_path.c_str(), lnk_args.c_str()));
            }

            // Release the pointer to the IPersistFile interface. 
            ppf->Release();
        }

        // Release the pointer to the IShellLink interface. 
        psl->Release();
    }
    */
}

bool Links::create_startup_folder_link(const char* lnk_name, const char* lnk_description, const char* lnk_target, const char* lnk_args)
{
    bool success = false;
    PWSTR pszPath;
    HRESULT hres = SHGetKnownFolderPath(FOLDERID_Startup, 0, NULL, &pszPath);

    if (SUCCEEDED(hres))
    {
        IShellLink* psl;
        bool success_createinstance = com.CreateInstance(CLSID_ShellLink, IID_IShellLink, (LPVOID*)&psl, NULL, NULL, NULL, NULL);
        if (!success_createinstance)
            return false;

        IPersistFile* ppf;

        // Set the path to the shortcut target and add the description. 
        psl->SetPath(lnk_target);
        psl->SetArguments(lnk_args);
        psl->SetDescription(lnk_description);

        // Query IShellLink for the IPersistFile interface, used for saving the 
        // shortcut in persistent storage. 
        hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);

        if (SUCCEEDED(hres))
        {
            WCHAR wsz[MAX_PATH];

            // Ensure that the string is Unicode. 
            MultiByteToWideChar(CP_ACP, 0, lnk_name, -1, wsz, MAX_PATH);

            std::wstring lnk_path = std::wstring(pszPath) + L"\\" + std::wstring(wsz);
            if (!ends_with(lnk_path, L".lnk"))
                lnk_path += L".lnk";

            // Add code here to check return value from MultiByteWideChar 
            // for success.

            // Save the link by calling IPersistFile::Save. 
            hres = ppf->Save(lnk_path.c_str(), TRUE);
            ppf->Release();

            success = true;
        }
        psl->Release();

        /*
        //  ------------------------------------------------------
 //  Initialize COM.
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (FAILED(hr))
        {
#ifdef DEBUG
            printf("CoInitializeEx failed: %x\n", hr);
#endif
            return false;
        }

        IShellLink* psl;

        // Get a pointer to the IShellLink interface. It is assumed that CoInitialize
        // has already been called.
        hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
        if (SUCCEEDED(hres))
        {
            IPersistFile* ppf;

            // Set the path to the shortcut target and add the description. 
            psl->SetPath(lnk_target);
            psl->SetArguments(lnk_args);
            psl->SetDescription(lnk_description);

            // Query IShellLink for the IPersistFile interface, used for saving the 
            // shortcut in persistent storage. 
            hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);

            if (SUCCEEDED(hres))
            {
                WCHAR wsz[MAX_PATH];

                // Ensure that the string is Unicode. 
                MultiByteToWideChar(CP_ACP, 0, lnk_name, -1, wsz, MAX_PATH);

                std::wstring lnk_path = std::wstring(pszPath) + L"\\" + std::wstring(wsz);
                if (!ends_with(lnk_path, L".lnk"))
                    lnk_path += L".lnk";

                // Add code here to check return value from MultiByteWideChar 
                // for success.

                // Save the link by calling IPersistFile::Save. 
                hres = ppf->Save(lnk_path.c_str(), TRUE);
                ppf->Release();

                success = true;
            }
            psl->Release();
        }
        */
    }
    else
    {
#ifdef DEBUG
        printf("Failed to get startup folder path\n");
#endif
        return false;
    }

    return success;
}

bool Links::remove_startup_folder_link(const char* lnk_name)
{
    bool success = false;
    PWSTR pszPath;
    HRESULT hres = SHGetKnownFolderPath(FOLDERID_Startup, 0, NULL, &pszPath);

    if (SUCCEEDED(hres))
    {
        WCHAR wsz[MAX_PATH];

        // Ensure that the string is Unicode. 
        MultiByteToWideChar(CP_ACP, 0, lnk_name, -1, wsz, MAX_PATH);

        std::wstring lnk_path = std::wstring(pszPath) + L"\\" + std::wstring(wsz);
        if (!ends_with(lnk_path, L".lnk"))
            lnk_path += L".lnk";

        BOOL res = DeleteFileW(lnk_path.c_str());

        if (res == TRUE)
        {
            success = true;
        }


    }
    else
    {
#ifdef DEBUG
        printf("Failed to get startup folder path\n");
#endif
        return false;
    }

    return success;
}

Link::Link(const char* lnk_path, const char* lnk_description, const char* lnk_target, const char* lnk_args)
{
    this->lnk_path = std::string(lnk_path);
    this->lnk_description = std::string(lnk_description);
    this->lnk_target = std::string(lnk_target);
    this->lnk_args = std::string(lnk_args);
}

bool ends_with(std::wstring const& value, std::wstring const& ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}