/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "registry.h"

Registry::Registry()
{
}

Registry::~Registry()
{
}

bool Registry::get_path(const char* reg_path, HKEY* root, const char** reg_subpath)
{
    const char* backslash = strstr(reg_path, "\\");
    if (backslash == 0)
    {
        return false;
    }

    if (memcmp(reg_path, "HKEY_CLASSES_ROOT", sizeof("HKEY_CLASSES_ROOT") - 1) == 0)
    {
        (*root) = HKEY_CLASSES_ROOT;
    }
    else if (memcmp(reg_path, "HKEY_CURRENT_CONFIG", sizeof("HKEY_CURRENT_CONFIG")-1) == 0)
    {
        (*root) = HKEY_CURRENT_CONFIG;
    }
    else if (memcmp(reg_path, "HKEY_CURRENT_USER", sizeof("HKEY_CURRENT_USER") - 1) == 0)
    {
        (*root) = HKEY_CURRENT_USER;
    }
    else if (memcmp(reg_path, "HKEY_LOCAL_MACHINE", sizeof("HKEY_LOCAL_MACHINE") - 1) == 0)
    {
        (*root) = HKEY_LOCAL_MACHINE;
    }
    else if (memcmp(reg_path, "HKEY_PERFORMANCE_DATA", sizeof("HKEY_PERFORMANCE_DATA") - 1) == 0)
    {
        (*root) = HKEY_PERFORMANCE_DATA;
    }
    else if (memcmp(reg_path, "HKEY_USERS", sizeof("HKEY_USERS") - 1) == 0)
    {
        (*root) = HKEY_USERS;
    }
    else
    {
        return false;
    }

    (*reg_subpath) = backslash + 1;

    return true;
}

std::list<RegEntry>* Registry::list_registry_keys(const char* reg_path)
{
    std::list<RegEntry>* reg_list = NULL;

    HKEY hKey;
    HKEY root;
    const char* sub_reg_path;
    bool success = this->get_path(reg_path, &root, &sub_reg_path);
    if (!success)
    {
        return NULL;
    }

    if (RegOpenKeyExA(root,
        sub_reg_path,
        0,
        KEY_READ,
        &hKey) == ERROR_SUCCESS
        )
    {
        TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
        DWORD    cbName;                   // size of name string 
        TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
        DWORD    cchClassName = MAX_PATH;  // size of class string 
        DWORD    cSubKeys = 0;               // number of subkeys 
        DWORD    cbMaxSubKey;              // longest subkey size 
        DWORD    cchMaxClass;              // longest class string 
        DWORD    cValues;              // number of values for key 
        DWORD    cchMaxValue;          // longest value name 
        DWORD    cbMaxValueData;       // longest value data 
        DWORD    cbSecurityDescriptor; // size of security descriptor 
        FILETIME ftLastWriteTime;      // last write time 

        DWORD i, retCode;

        TCHAR  achValue[MAX_VALUE_NAME];
        DWORD cchValue = MAX_VALUE_NAME;

        // Get the class name and the value count. 
        retCode = RegQueryInfoKeyA(
            hKey,                    // key handle 
            achClass,                // buffer for class name 
            &cchClassName,           // size of class string 
            NULL,                    // reserved 
            &cSubKeys,               // number of subkeys 
            &cbMaxSubKey,            // longest subkey size 
            &cchMaxClass,            // longest class string 
            &cValues,                // number of values for this key 
            &cchMaxValue,            // longest value name 
            &cbMaxValueData,         // longest value data 
            &cbSecurityDescriptor,   // security descriptor 
            &ftLastWriteTime);       // last write time 

        // Enumerate the key values. 

        if (cValues)
        {
            reg_list = new std::list<RegEntry>();

            for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++)
            {
                cchValue = MAX_VALUE_NAME;
                achValue[0] = '\0';
                DWORD pType;
                DWORD data_size = 0;
                //LPBYTE nameOfValue = (LPBYTE)malloc(data_size);
                retCode = RegEnumValueA(hKey, i,
                    achValue,
                    &cchValue,
                    NULL,
                    &pType,
                    NULL,
                    &data_size);

                if (retCode != ERROR_SUCCESS)
                {
#ifdef DEBUG
                    printf("RegEnumValue failure: %d\n", GetLastError());
#endif
                    continue;
                }

                if (pType != REG_SZ)
                {
                    continue;
                }

                cchValue = MAX_VALUE_NAME;
                achValue[0] = '\0';

                LPBYTE nameOfValue = (LPBYTE)malloc(data_size);

                retCode = RegEnumValueA(hKey, i,
                    achValue,
                    &cchValue,
                    NULL,
                    &pType,
                    nameOfValue,
                    &data_size);

                if (retCode == ERROR_SUCCESS)
                {
                    reg_list->push_back(RegEntry(achValue, (char*)nameOfValue));
                }

                free(nameOfValue);
            }
        }
    }

    RegCloseKey(hKey);

    return reg_list;
}

bool Registry::set_registry(const char* reg_path, const char* name, const char* value)
{
    HKEY hkey;
    HKEY root;
    const char* sub_reg_path;
    printf("A\n");
    bool success = this->get_path(reg_path, &root, &sub_reg_path);
    printf("B\n");
    if (!success)
    {
        printf("D\n");
        return NULL;
    }

    DWORD dwDisposition;
    printf("C\n");
    if (RegCreateKeyExA(root, sub_reg_path, 0, NULL, 0, KEY_WRITE, NULL, &hkey, &dwDisposition) == ERROR_SUCCESS) {
        DWORD dwType, dwSize;
        dwType = REG_DWORD;
        dwSize = sizeof(DWORD);
        DWORD rofl = 1;
        LSTATUS status = RegSetValueExA(hkey, name, 0, REG_SZ, (LPBYTE)value, strlen(value) + 1); // does not create anything
        RegCloseKey(hkey);

        if (status == ERROR_SUCCESS)
            return true;
        else
            return false;
    }
    else
        return false;
}

bool Registry::remove_registry(const char* reg_path, const char* name)
{
    HKEY root;
    const char* sub_reg_path;
    bool success = this->get_path(reg_path, &root, &sub_reg_path);
    if (!success)
    {
        return NULL;
    }

    LSTATUS status = RegDeleteKeyValueA(root, sub_reg_path, name);

    if (status == ERROR_SUCCESS)
        return true;
    else
        return false;

}


RegEntry::RegEntry(const char* name, const char* value)
{
    this->name = std::string(name);
    this->value = std::string(value);
}