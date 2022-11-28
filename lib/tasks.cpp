/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "tasks.h"

Tasks::Tasks()
{
}

Tasks::~Tasks()
{
}

std::list<Task>* Tasks::list_tasks()
{
    std::list<Task>* task_list = NULL;

    HRESULT hr;
    ITaskService* pService = NULL;
    bool success = this->com.CreateInstance(CLSID_TaskScheduler, IID_ITaskService, (LPVOID*)&pService, NULL, NULL, NULL, NULL);
    if (!success)
        return NULL;

    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("ITaskService::Connect failed: %x", hr);
#endif
        pService->Release();
        return NULL;
    }

    //  ------------------------------------------------------
    //  Get the pointer to the root task folder.
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);

    task_list = new std::list<Task>();

    this->list_task_subfolder(pRootFolder, hr, L"", task_list);

    pService->Release();
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot get Root Folder pointer: %x", hr);
#endif
        return NULL;
    }

    return task_list;
}

void Tasks::list_task_subfolder(ITaskFolder* rootFolder, HRESULT hr, std::wstring previous_folder, std::list<Task>* task_list)
{
    /* 
        source: https://www.writebug.com/git/jiejie/Autoruns/src/branch/master/src/tasks.cpp
    */

    ITaskFolderCollection* pFolders = NULL;
    hr = rootFolder->GetFolders(0, &pFolders);

    if (FAILED(hr))
    {
        return;
    }

    LONG numFolders = 0;
    hr = pFolders->get_Count(&numFolders);
    if (FAILED(hr))
    {
        return;
    }

    for (LONG i = 0; i < numFolders; i++)
    {
        ITaskFolder* pRootFolder = NULL;
        hr = pFolders->get_Item(_variant_t(i + 1), &pRootFolder);
        if (SUCCEEDED(hr))
        {
            BSTR name = NULL;
            hr = pRootFolder->get_Name(&name);
            if (FAILED(hr))
            {
                return;
            }
            
            std::wstring current_folder = previous_folder + L"\\" + std::wstring(name);
            SysFreeString(name);
#ifdef DEBUG
            //wprintf(L"Folder Name: %s\n", current_folder.c_str());
#endif

            this->list_task_subfolder(pRootFolder, hr, current_folder, task_list);


            IRegisteredTaskCollection* pTaskCollection = NULL;
            hr = pRootFolder->GetTasks(NULL, &pTaskCollection);
            LONG numTasks = 0;
            pTaskCollection->get_Count(&numTasks);

            for (LONG i = 0; i < numTasks; i++)
            {
                IRegisteredTask* pRegisteredTask = NULL;
                hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);

                if (SUCCEEDED(hr))
                {
                    BSTR taskName = NULL;
                    hr = pRegisteredTask->get_Name(&taskName);
                    if (SUCCEEDED(hr))
                    {
                        std::wstring task_name_str = std::wstring(taskName);
                        TASK_STATE taskState = TASK_STATE_UNKNOWN;
                        std::wstring task_description_str = L"";
                        std::wstring task_action_str = L"";

                        // Task name
                        SysFreeString(taskName);

                        // Task state
                        hr = pRegisteredTask->get_State(&taskState);
                        if (SUCCEEDED(hr))
                        { }
                        else
                        {
#ifdef DEBUG
                            printf("Cannot get the registered task state: %x\n", hr);
#endif
                        }

                        // Task description
                        BSTR taskDescription = NULL;
                        ITaskDefinition* taskDefinition = NULL;
                        IRegistrationInfo* taskRegistrationInfo = NULL;
                        IActionCollection* taskActions = NULL;
                        hr = pRegisteredTask->get_Definition(&taskDefinition);
                        if (SUCCEEDED(hr))
                        {
                            hr = taskDefinition->get_RegistrationInfo(&taskRegistrationInfo);
                            if (SUCCEEDED(hr))
                            {
                                hr = taskRegistrationInfo->get_Description(&taskDescription);
                                if (SUCCEEDED(hr))
                                {
                                    if (taskDescription != NULL)
                                        task_description_str = std::wstring(taskDescription);
                                    SysFreeString(taskDescription);
                                }
                                else
                                {
#ifdef DEBUG
                                    printf("Cannot get the registered task description: %x\n", hr);
#endif
                                }

                                taskRegistrationInfo->Release();
                            }
                            else
                            {
#ifdef DEBUG
                                printf("Cannot get the registered task registration_info: %x\n", hr);
#endif
                            }

                            hr = taskDefinition->get_Actions(&taskActions);
                            if (SUCCEEDED(hr))
                            {
                                IAction* action = NULL;
                                hr = taskActions->get_Item(1, &action);
                                if (SUCCEEDED(hr))
                                {
                                    IExecAction* execAction = NULL;

                                    hr = action->QueryInterface(IID_IAction, (void**)&execAction);
                                    if (SUCCEEDED(hr))
                                    {
                                        action->Release();

                                        BSTR imagePath = NULL;
                                        hr = execAction->get_Path(&imagePath);
                                        if (SUCCEEDED(hr))
                                        {
                                            if (imagePath != NULL)
                                                task_action_str = std::wstring(imagePath);
                                            SysFreeString(imagePath);
                                        }
                                        else
                                        {
#ifdef DEBUG
                                            printf("Cannot get the registered task action path: %x\n", hr);
#endif
                                        }

                                        // Releasing this makes taskDefinition->Release() crash...
                                        //execAction->Release();
                                    }
                                    else
                                    {
#ifdef DEBUG
                                        printf("Can not query action interface: %lx\n", hr);
#endif
                                    }

                                    action->Release();
                                }
                                else
                                {
#ifdef DEBUG
                                    printf("Cannot get the registered task action 1: %x\n", hr);
#endif
                                }

                                taskActions->Release();
                            }
                            else
                            {
#ifdef DEBUG
                                printf("Cannot get the registered task registration_info: %x\n", hr);
#endif
                            }
                            taskDefinition->Release();
                        }
                        else
                        {
#ifdef DEBUG
                            printf("Cannot get the registered task state: %x\n", hr);
#endif
                        }

                        task_list->push_back(Task(current_folder, task_name_str, taskState, task_description_str, task_action_str));
                    }
                    else
                    {
#ifdef DEBUG
                        printf("Cannot get the registered task name: %x\n", hr);
#endif
                    }


                    pRegisteredTask->Release();
                }
                else
                {
#ifdef DEBUG
                    printf("Cannot get the registered task item at index=%d: %x\n", i + 1, hr);
#endif
                }
            }

        }
    }

    pFolders->Release();
}

bool Tasks::create_task(std::wstring task_folder, std::wstring task_name, std::wstring exe_path)
{
    HRESULT hr;
    ITaskService* pService = NULL;
    bool success = this->com.CreateInstance(CLSID_TaskScheduler, IID_ITaskService, (LPVOID*)&pService, NULL, NULL, NULL, NULL);
    if (!success)
        return false;

    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("ITaskService::Connect failed: %x\n", hr);
#endif
        pService->Release();
        return false;
    }

    //  ------------------------------------------------------
    //  Get the pointer to the root task folder.  
    //  This folder will hold the new task that is registered.
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(task_folder.c_str()), &pRootFolder);
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot get Root Folder pointer: %x\n", hr);
#endif
        pService->Release();
        return false;
    }

    //  If the same task exists, remove it.
    pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), 0);

    //  Create the task builder object to create the task.
    ITaskDefinition* pTask = NULL;
    hr = pService->NewTask(0, &pTask);

    pService->Release();  // COM clean up.  Pointer is no longer used.
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Failed to create a task definition: %x\n", hr);
#endif
        pRootFolder->Release();
        return false;
    }


    //  ------------------------------------------------------
    //  Get the registration info for setting the identification.
    IRegistrationInfo* pRegInfo = NULL;
    hr = pTask->get_RegistrationInfo(&pRegInfo);
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot get identification pointer: %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }

    hr = pRegInfo->put_Author(_bstr_t(L"Author Name"));
    pRegInfo->Release();
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot put identification info: %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }

    //  ------------------------------------------------------
    //  Create the settings for the task
    ITaskSettings* pSettings = NULL;
    hr = pTask->get_Settings(&pSettings);
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot get settings pointer: %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }

    //  Set setting values for the task. 
    hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
    pSettings->Release();
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot put setting info: %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }


    //  ------------------------------------------------------
    //  Get the trigger collection to insert the boot trigger.
    ITriggerCollection* pTriggerCollection = NULL;
    hr = pTask->get_Triggers(&pTriggerCollection);
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot get trigger collection: %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }

    //  Add the boot trigger to the task.
    ITrigger* pTrigger = NULL;
    hr = pTriggerCollection->Create(TASK_TRIGGER_BOOT, &pTrigger);
    pTriggerCollection->Release();
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot create the trigger: %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }

    IBootTrigger* pBootTrigger = NULL;
    hr = pTrigger->QueryInterface(
        IID_IBootTrigger, (void**)&pBootTrigger);
    pTrigger->Release();
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("QueryInterface call failed for IBootTrigger: %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }

    hr = pBootTrigger->put_Id(_bstr_t(L"Trigger1"));
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot put the trigger ID: %x\n", hr);
#endif
    }

    //  Set the task to start at a certain time. The time 
    //  format should be YYYY-MM-DDTHH:MM:SS(+-)(timezone).
    //  For example, the start boundary below
    //  is January 1st 2005 at 12:05
    /*
    hr = pBootTrigger->put_StartBoundary(_bstr_t(L"2020-01-01T01:00:00"));
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("\nCannot put the start boundary: %x\n", hr);
#endif
    }

    hr = pBootTrigger->put_EndBoundary(_bstr_t(L"2015-05-02T08:00:00"));
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot put the end boundary: %x\n", hr);
#endif
    }
    */

    // Delay the task to start 30 seconds after system start. 
    hr = pBootTrigger->put_Delay(_bstr_t(L"PT30S"));
    pBootTrigger->Release();
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot put delay for boot trigger: %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }


    //  ------------------------------------------------------
    //  Add an Action to the task. This task will execute Notepad.exe.     
    IActionCollection* pActionCollection = NULL;

    //  Get the task action collection pointer.
    hr = pTask->get_Actions(&pActionCollection);
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot get Task collection pointer: %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }

    //  Create the action, specifying it as an executable action.
    IAction* pAction = NULL;
    hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
    pActionCollection->Release();
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot create the action: %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }

    IExecAction* pExecAction = NULL;
    //  QI for the executable task pointer.
    hr = pAction->QueryInterface(
        IID_IExecAction, (void**)&pExecAction);
    pAction->Release();
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("QueryInterface call failed for IExecAction: %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }

    //  Set the path of the executable to Notepad.exe.
    hr = pExecAction->put_Path(_bstr_t(exe_path.c_str()));
    pExecAction->Release();
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot set path of executable: %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }


    //  ------------------------------------------------------
    //  Save the task in the root folder.
    IRegisteredTask* pRegisteredTask = NULL;
    VARIANT varPassword;
    varPassword.vt = VT_EMPTY;
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(task_name.c_str()),
        pTask,
        TASK_CREATE_OR_UPDATE,
        _variant_t(L"S-1-5-19"), // Local service
        varPassword,
        TASK_LOGON_SERVICE_ACCOUNT,
        _variant_t(L""),
        &pRegisteredTask);
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Error saving the Task : %x\n", hr);
#endif
        pRootFolder->Release();
        pTask->Release();
        return false;
    }

    printf("\n Success! Task successfully registered. ");

    //  Clean up.
    pRootFolder->Release();
    pTask->Release();
    pRegisteredTask->Release();
    return true;
}

bool Tasks::delete_task(std::wstring task_folder, std::wstring task_name)
{
    HRESULT hr;
    ITaskService* pService = NULL;
    bool success = this->com.CreateInstance(CLSID_TaskScheduler, IID_ITaskService, (LPVOID*)&pService, NULL, NULL, NULL, NULL);
    if (!success)
        return false;

    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("ITaskService::Connect failed: %x\n", hr);
#endif
        pService->Release();
        return false;
    }

    //  ------------------------------------------------------
    //  Get the pointer to the root task folder.  
    //  This folder will hold the new task that is registered.
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(task_folder.c_str()), &pRootFolder);
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot get Root Folder pointer: %x\n", hr);
#endif
        pService->Release();
        return false;
    }

    //  If the same task exists, remove it.
    hr = pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), 0);

    pService->Release();
    pRootFolder->Release();

    if (FAILED(hr))
    {
        return false;
    }

    return true;
}

bool Tasks::start_task(std::wstring task_folder, std::wstring task_name)
{
    HRESULT hr;
    ITaskService* pService = NULL;
    bool success = this->com.CreateInstance(CLSID_TaskScheduler, IID_ITaskService, (LPVOID*)&pService, NULL, NULL, NULL, NULL);
    if (!success)
        return false;

    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("ITaskService::Connect failed: %x\n", hr);
#endif
        pService->Release();
        return false;
    }

    //  ------------------------------------------------------
    //  Get the pointer to the root task folder.  
    //  This folder will hold the new task that is registered.
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(task_folder.c_str()), &pRootFolder);
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot get Root Folder pointer: %x\n", hr);
#endif
        pService->Release();
        return false;
    }

    //  If the same task exists, remove it.
    IRegisteredTask* task = NULL;
    hr = pRootFolder->GetTask(_bstr_t(task_name.c_str()), &task);
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot get Root Folder pointer: %x\n", hr);
#endif
        pService->Release();
        return false;
    }

    VARIANT v;
    v.vt = VT_EMPTY;
    IRunningTask* running_task = NULL;
    hr = task->Run(v, &running_task);
    if (SUCCEEDED(hr))
    {
        running_task->Release();
    }

    task->Release();
    pService->Release();
    pRootFolder->Release();

    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Failed to start task: %x\n", hr);
#endif
        return false;
    }

    return true;
}

bool Tasks::stop_task(std::wstring task_folder, std::wstring task_name)
{
    HRESULT hr;
    ITaskService* pService = NULL;
    bool success = this->com.CreateInstance(CLSID_TaskScheduler, IID_ITaskService, (LPVOID*)&pService, NULL, NULL, NULL, NULL);
    if (!success)
        return false;

    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("ITaskService::Connect failed: %x\n", hr);
#endif
        pService->Release();
        return false;
    }

    //  ------------------------------------------------------
    //  Get the pointer to the root task folder.  
    //  This folder will hold the new task that is registered.
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(task_folder.c_str()), &pRootFolder);
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot get Root Folder pointer: %x\n", hr);
#endif
        pService->Release();
        return false;
    }

    //  If the same task exists, remove it.
    IRegisteredTask* task = NULL;
    hr = pRootFolder->GetTask(_bstr_t(task_name.c_str()), &task);
    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Cannot get Root Folder pointer: %x\n", hr);
#endif
        pService->Release();
        return false;
    }


    hr = task->Stop(NULL);

    task->Release();
    pService->Release();
    pRootFolder->Release();

    if (FAILED(hr))
    {
#ifdef DEBUG
        printf("Failed to start task: %x\n", hr);
#endif
        return false;
    }

    return true;
}

Task::Task(std::wstring task_folder, std::wstring task_name, TASK_STATE task_state, std::wstring task_description, std::wstring task_action)
{
    this->task_folder = task_folder;
    this->task_name = task_name;
    this->task_description = task_description;
    this->task_action = task_action;

    switch (task_state)
    {
    case TASK_STATE_DISABLED:
        this->task_state = std::wstring(L"disabled");
        break;
    case TASK_STATE_QUEUED:
        this->task_state = std::wstring(L"queued");
        break;
    case TASK_STATE_READY:
        this->task_state = std::wstring(L"ready");
        break;
    case TASK_STATE_RUNNING:
        this->task_state = std::wstring(L"running");
        break;
    default:
        this->task_state = std::wstring(L"unknown");
    }

}