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

std::list<std::string>* Registry::list_registry_subkeys(const char* reg_path)
{
    std::list<std::string>* subkey_list = NULL;

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

        subkey_list = new std::list<std::string>();

        if (cSubKeys)
        {
            for (i = 0; i < cSubKeys; i++)
            {
                cbName = MAX_KEY_LENGTH;
                retCode = RegEnumKeyEx(hKey, i,
                    achKey,
                    &cbName,
                    NULL,
                    NULL,
                    NULL,
                    &ftLastWriteTime);
                if (retCode == ERROR_SUCCESS)
                {
                    subkey_list->push_back(std::string(achKey));
                }
            }
        }


        RegCloseKey(hKey);
    }

    return subkey_list;
}

std::list<RegEntry>* Registry::list_registry_entries(const char* reg_path)
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

                if (pType == REG_BINARY)
                {
                    cchValue = MAX_VALUE_NAME;
                    achValue[0] = '\0';

                    LPBYTE value = (LPBYTE)malloc(data_size);

                    retCode = RegEnumValueA(hKey, i,
                        achValue,
                        &cchValue,
                        NULL,
                        &pType,
                        value,
                        &data_size);

                    if (retCode == ERROR_SUCCESS)
                    {
                        reg_list->push_back(RegEntry(achValue, "REG_BINARY", std::string((char*)value, data_size)));
                    }
                    else
                    {
                        reg_list->push_back(RegEntry(achValue, "REG_BINARY", "<Error>"));
                    }

                    free(value);

                }
                else if (pType == REG_DWORD)
                {
                    cchValue = MAX_VALUE_NAME;
                    achValue[0] = '\0';

                    DWORD value;

                    retCode = RegEnumValueA(hKey, i,
                        achValue,
                        &cchValue,
                        NULL,
                        &pType,
                        (LPBYTE)&value,
                        &data_size);

                    if (retCode == ERROR_SUCCESS)
                    {
                        reg_list->push_back(RegEntry(achValue, "REG_DWORD", std::to_string(value)));
                    }
                    else
                    {
                        reg_list->push_back(RegEntry(achValue, "REG_DWORD", "<Error>"));
                    }
                }
                else if (pType == REG_DWORD_LITTLE_ENDIAN)
                {
                    reg_list->push_back(RegEntry(achValue, "REG_DWORD_LITTLE_ENDIAN", "<Unsupported>"));
                }
                else if (pType == REG_DWORD_BIG_ENDIAN)
                {
                    reg_list->push_back(RegEntry(achValue, "REG_DWORD_BIG_ENDIAN", "<Unsupported>"));
                }
                else if (pType == REG_EXPAND_SZ)
                {
                    cchValue = MAX_VALUE_NAME;
                    achValue[0] = '\0';

                    LPBYTE value = (LPBYTE)malloc(data_size);

                    retCode = RegEnumValueA(hKey, i,
                        achValue,
                        &cchValue,
                        NULL,
                        &pType,
                        value,
                        &data_size);

                    if (retCode == ERROR_SUCCESS)
                    {
                        reg_list->push_back(RegEntry(achValue, "REG_EXPAND_SZ", (char*)value));
                    }
                    else
                    {
                        reg_list->push_back(RegEntry(achValue, "REG_EXPAND_SZ", "<Error>"));
                    }

                    free(value);
                }
                else if (pType == REG_LINK)
                {
                    reg_list->push_back(RegEntry(achValue, "REG_LINK", "<Unsupported>"));
                }
                else if (pType == REG_MULTI_SZ)
                {
                    cchValue = MAX_VALUE_NAME;
                    achValue[0] = '\0';

                    LPBYTE value = (LPBYTE)malloc(data_size);

                    retCode = RegEnumValueA(hKey, i,
                        achValue,
                        &cchValue,
                        NULL,
                        &pType,
                        value,
                        &data_size);

                    // replace \0 with , expect the last 2
                    for (int i = 0; i < data_size - 2; i++)
                    {
                        if (value[i] == '\0')
                        {
                            value[i] = ',';
                        }
                    }

                    if (retCode == ERROR_SUCCESS)
                    {
                        reg_list->push_back(RegEntry(achValue, "REG_MULTI_SZ", (char*)value));
                    }
                    else
                    {
                        reg_list->push_back(RegEntry(achValue, "REG_MULTI_SZ", "<Error>"));
                    }

                    free(value);
                }
                else if (pType == REG_NONE)
                {
                    reg_list->push_back(RegEntry(achValue, "REG_NONE", "<Unsupported>"));
                }
                else if (pType == REG_QWORD)
                {
                    cchValue = MAX_VALUE_NAME;
                    achValue[0] = '\0';

                    unsigned long long value;

                    retCode = RegEnumValueA(hKey, i,
                        achValue,
                        &cchValue,
                        NULL,
                        &pType,
                        (LPBYTE)&value,
                        &data_size);

                    if (retCode == ERROR_SUCCESS)
                    {
                        reg_list->push_back(RegEntry(achValue, "REG_QWORD", std::to_string(value)));
                    }
                    else
                    {
                        reg_list->push_back(RegEntry(achValue, "REG_QWORD", "<Error>"));
                    }
                }
                else if (pType == REG_QWORD_LITTLE_ENDIAN)
                {
                    reg_list->push_back(RegEntry(achValue, "REG_QWORD_LITTLE_ENDIAN", "<Unsupported>"));
                }
                else if (pType == REG_SZ)
                {
                    cchValue = MAX_VALUE_NAME;
                    achValue[0] = '\0';

                    LPBYTE value = (LPBYTE)malloc(data_size);

                    retCode = RegEnumValueA(hKey, i,
                        achValue,
                        &cchValue,
                        NULL,
                        &pType,
                        value,
                        &data_size);

                    if (retCode == ERROR_SUCCESS)
                    {
                        reg_list->push_back(RegEntry(achValue, "REG_SZ", (char*)value));
                    }
                    else
                    {
                        reg_list->push_back(RegEntry(achValue, "REG_SZ", "<Error>"));
                    }

                    free(value);
                }
                
            }
        }

        RegCloseKey(hKey);
    }

    return reg_list;
}

bool Registry::set_entry_sz(const char* reg_path, const char* name, const char* value)
{
    HKEY hkey;
    HKEY root;
    const char* sub_reg_path;
    bool success = this->get_path(reg_path, &root, &sub_reg_path);
    if (!success)
    {
        return NULL;
    }

    DWORD dwDisposition;
    if (RegCreateKeyExA(root, sub_reg_path, 0, NULL, 0, KEY_WRITE, NULL, &hkey, &dwDisposition) == ERROR_SUCCESS) {
        DWORD dwType, dwSize;
        dwType = REG_DWORD;
        dwSize = sizeof(DWORD);
        DWORD rofl = 1;
        LSTATUS status = RegSetValueExA(hkey, name, 0, REG_SZ, (LPBYTE)value, strlen(value) + 1); 
        RegCloseKey(hkey);

        if (status == ERROR_SUCCESS)
            return true;
        else
            return false;
    }
    else
        return false;
}

bool Registry::set_entry_dword(const char* reg_path, const char* name, DWORD value)
{
    HKEY hkey;
    HKEY root;
    const char* sub_reg_path;
    bool success = this->get_path(reg_path, &root, &sub_reg_path);
    if (!success)
    {
        return NULL;
    }

    DWORD dwDisposition;
    if (RegCreateKeyExA(root, sub_reg_path, 0, NULL, 0, KEY_WRITE, NULL, &hkey, &dwDisposition) == ERROR_SUCCESS) {
        DWORD dwType, dwSize;
        dwType = REG_DWORD;
        dwSize = sizeof(DWORD);
        DWORD rofl = 1;
        LSTATUS status = RegSetValueExA(hkey, name, 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
        RegCloseKey(hkey);

        if (status == ERROR_SUCCESS)
            return true;
        else
            return false;
    }
    else
        return false;
}

bool Registry::set_entry_multi_sz(const char* reg_path, const char* name, const char* value)
{
    HKEY hkey;
    HKEY root;
    const char* sub_reg_path;
    bool success = this->get_path(reg_path, &root, &sub_reg_path);
    if (!success)
    {
        return NULL;
    }

    DWORD dwDisposition;
    if (RegCreateKeyExA(root, sub_reg_path, 0, NULL, 0, KEY_WRITE, NULL, &hkey, &dwDisposition) == ERROR_SUCCESS) {

        char* buffer = (char*)malloc(strlen(value) + 2);
        strncpy_s(buffer, strlen(value) + 2, value, strlen(value));
        // Add double \0
        buffer[strlen(value)] = 0;
        buffer[strlen(value) + 1] = 0;
        // Replace , by \0
        for (int i = 0; i < strlen(value); i++)
        {
            if (buffer[i] == ',')
            {
                buffer[i] = 0;
            }
        }

        DWORD dwType, dwSize;
        dwType = REG_DWORD;
        dwSize = sizeof(DWORD);
        DWORD rofl = 1;
        LSTATUS status = RegSetValueExA(hkey, name, 0, REG_MULTI_SZ, (LPBYTE)buffer, strlen(value) + 2);
        RegCloseKey(hkey);

        free(buffer);

        if (status == ERROR_SUCCESS)
            return true;
        else
            return false;
    }
    else
        return false;
}


bool Registry::remove_entry(const char* reg_path, const char* name)
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

bool Registry::delete_key(const char* reg_path)
{
    HKEY root;
    const char* sub_reg_path;
    bool success = this->get_path(reg_path, &root, &sub_reg_path);
    if (!success)
    {
        return NULL;
    }

    LSTATUS status = SHDeleteKeyA(root, sub_reg_path);

    if (status == ERROR_SUCCESS)
        return true;
    else
        return false;

}

std::list<COM_object>* Registry::list_com()
{
    std::list<COM_object>* com_list = NULL;

    std::list<std::string>* subkeys = this->list_registry_subkeys("HKEY_LOCAL_MACHINE\\Software\\Classes");
    if (subkeys != NULL)
    {
        com_list = new std::list<COM_object>();

        for (std::list<std::string>::const_iterator iterator = subkeys->begin(), end = subkeys->end(); iterator != end; ++iterator) {

            std::string path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\" + (*iterator) + "\\CLSID";

            HKEY hKey;
            HKEY root;
            const char* sub_reg_path;
            bool success = this->get_path(path.c_str(), &root, &sub_reg_path);
            if (!success)
            {
                continue;
            }

            if (RegOpenKeyExA(root,
                sub_reg_path,
                0,
                KEY_READ,
                &hKey) == ERROR_SUCCESS
                )
            {

                DWORD size = 0;
                LSTATUS success = RegGetValueA(hKey, NULL, "", RRF_RT_REG_SZ, NULL, NULL, &size);
                if (success != ERROR_SUCCESS)
                {
                    RegCloseKey(hKey);
                    continue;
                }

                const char* clsid = (char*)malloc(size);

                success = RegGetValueA(hKey, NULL, "", RRF_RT_REG_SZ, NULL, (PVOID)clsid, &size);
                if (success != ERROR_SUCCESS)
                {
                    RegCloseKey(hKey);
                    continue;
                }

                com_list->push_back(COM_object((*iterator).c_str(), clsid));
            }
        }
    }

    return com_list;
}



RegEntry::RegEntry(const char* name, const char* type, std::string value)
{
    this->name = std::string(name);
    this->type = std::string(type);
    this->value = value;
}

COM_object::COM_object(const char* name, const char* clsid)
{
    this->name = std::string(name);
    this->clsid = std::string(clsid);
}