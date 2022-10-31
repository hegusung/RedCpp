/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "net.h"

Net::Net()
{
}

Net::~Net()
{
}

std::list<std::wstring> Net::get_local_groups(const char* user)
{
    std::list<std::wstring> group_list;

    LPLOCALGROUP_USERS_INFO_0  pBuf = NULL;
    DWORD dwLevel = 0;
    DWORD dwFlags = LG_INCLUDE_INDIRECT;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;

    wchar_t* user_w;
    if (user == NULL)
    {
        user_w = new wchar_t[UNLEN + 1]();
        DWORD username_len = UNLEN + 1;
        GetUserNameW(user_w, &username_len);
    }
    else
    {
        size_t wn;
        mbstate_t state = { 0 };
        if (mbsrtowcs_s(&wn, NULL, 0, &user, 0, &state) != 0)
        {
#ifdef DEBUG
            printf("The array contains an invalid multibyte character.\n");
#endif
            return group_list;
        }

        user_w = new wchar_t[wn + 1]();
        if (mbsrtowcs_s(&wn, user_w, (size_t)(wn + 1), &user, strlen(user), &state) != 0)
        {
#ifdef DEBUG
            printf("The array contains an invalid multibyte character.\n");
#endif
            return group_list;
        }
    }
    

    //
    // Call the NetUserGetGroups function, specifying level 0.
    //
    nStatus = NetUserGetLocalGroups(NULL,
        user_w,
        dwLevel,
        dwFlags,
        (LPBYTE*)&pBuf,
        dwPrefMaxLen,
        &dwEntriesRead,
        &dwTotalEntries);
    //
    // If the call succeeds,
    //
    if (nStatus == NERR_Success)
    {
        LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
        DWORD i;
        DWORD dwTotalCount = 0;

        if ((pTmpBuf = pBuf) != NULL)
        {
            //
            // Loop through the entries; 
            //  print the name of the global groups 
            //  to which the user belongs.
            //
            for (i = 0; i < dwEntriesRead; i++)
            {

                if (pTmpBuf == NULL)
                {
#ifdef DEBUG
                    printf("An access violation has occurred\n");
#endif
                    break;
                }

                group_list.push_back(std::wstring(pTmpBuf->lgrui0_name));

                pTmpBuf++;
                dwTotalCount++;
            }
        }
    }
    else
    {
#ifdef DEBUG
        printf("A system error has occurred : %d\n", nStatus);
#endif
    }
    //
    // Free the allocated buffer.
    //
    if (pBuf != NULL)
        NetApiBufferFree(pBuf);

    delete[] user_w;

    return group_list;
}

std::list<std::wstring> Net::get_global_groups(const char* user)
{
	std::list<std::wstring> group_list;

	LPGROUP_USERS_INFO_0 pBuf = NULL;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	NET_API_STATUS nStatus;

    wchar_t* user_w;
    if (user == NULL)
    {
        user_w = new wchar_t[UNLEN + 1]();
        DWORD username_len = UNLEN + 1;
        GetUserNameW(user_w, &username_len);
    }
    else
    {
        size_t wn;
        mbstate_t state = { 0 };
        if (mbsrtowcs_s(&wn, NULL, 0, &user, 0, &state) != 0)
        {
#ifdef DEBUG
            printf("The array contains an invalid multibyte character.\n");
#endif
            return group_list;
        }

        user_w = new wchar_t[wn + 1]();
        if (mbsrtowcs_s(&wn, user_w, (size_t)(wn + 1), &user, strlen(user), &state) != 0)
        {
#ifdef DEBUG
            printf("The array contains an invalid multibyte character.\n");
#endif
            return group_list;
        }
    }

   //
   // Call the NetUserGetGroups function, specifying level 0.
   //
    nStatus = NetUserGetGroups(NULL,
        user_w,
        dwLevel,
        (LPBYTE*)&pBuf,
        dwPrefMaxLen,
        &dwEntriesRead,
        &dwTotalEntries);
    //
    // If the call succeeds,
    //
    if (nStatus == NERR_Success)
    {
        LPGROUP_USERS_INFO_0 pTmpBuf;
        DWORD i;
        DWORD dwTotalCount = 0;

        if ((pTmpBuf = pBuf) != NULL)
        {
            //
            // Loop through the entries; 
            //  print the name of the global groups 
            //  to which the user belongs.
            //
            for (i = 0; i < dwEntriesRead; i++)
            {

                if (pTmpBuf == NULL)
                {
#ifdef DEBUG
                    printf("An access violation has occurred\n");
#endif
                    break;
                }

                if(wcscmp(pTmpBuf->grui0_name, L"None") != 0)
                    group_list.push_back(std::wstring(pTmpBuf->grui0_name));

                pTmpBuf++;
                dwTotalCount++;
            }
        }
    }
    else
    {
#ifdef DEBUG
        printf("A system error has occurred : %d\n", nStatus);
#endif
    }
    //
    // Free the allocated buffer.
    //
    if (pBuf != NULL)
        NetApiBufferFree(pBuf);

    delete[] user_w;

    return group_list;
}