# ArkToolDrv
## An ark tool's driver<br/>
### This repository has been moved to [here(ArkProtect)](https://github.com/AzureGreen/ArkProtect), and this one won't update any more.

```
This is an Ark tool's driver part. Maybe there remains some bugs..<br/>
first of all, I used Neither_IO to establish the connect between ring3 and ring0
```

## ProcessModule.
### 1.Enum Process By Force.
```
  Each time, add ProcessId by 4 and test whether the id is valid.
  When I need to get process's full path, I used sectionobject to get fileobject, then I get the filename
in this structure.
```	

### 2.Enum Thread By ListEntry.
```
  There are two Lists which we can travel them to find all thread in the target process
  · _EPROCESS --> ThreadListHead & _ETHREAD --> ThreadListEntry
  · _KPROCESS --> ThreadListHead & _KTHREAD --> ThreadListEntry
```	

### 3.Enum ProcessModule By Ldr.
```
  In the Structure of _PEB, we can get a member called "Ldr", three list are existing in it, which recorded 
all modules >the process had loaded. so we can travel them respectively.
```

### 4.Process Privilege.
```
  Enum and adjust privilege by a a series of NTfunctions concerning ProcessToken
```

### 5.Enum Process Handle.
```
  ZwQuerySystemInformation + SystemHandleInformation
```	

### 6.Enum Process Window.
```
  NtUserBuildHwndList + NtUserQueryWindow (get from SSSDT)
```

### 7.Enum Process Memory.
```
  Use NtQueryVirtualMemory by force from 0 to MaxUserSpaceAddress
```	

### 8.Kill Process.
```
  Just used a NTFunction--ZwTerminateProcess
```	

## DriverModule.
### 1.Enum Sys Module.
```
   Firstly, travel LdrDataTableEntry.
   Then, travel DirectoryObject (a hash table), Attention, travel device chain and device satck
```

### 2.Unload Sys Module.
```
   If sys has an Unload dispatch, then just call it
   If Sys does not have an Unload dispatch, then we need to realize it manually
```  
  
## KrnlModule.
### 1.Callbacks.
```
   Enum -->
     · LoadImageCallback, CreateThreadCallback, CreateProcessCallback are similiar. They are all in an array.
     · RegisterCallback, BugCheckCallback, BugCheckReasonCallback, ShutDownCallback are ListEntry Structure.

   Remove -->
     call Remove function
     · LoadImageCallback, CreateThreadCallback, CreateProcessCallback: use callbackAddress
     · RegisterCallback: use Cookie
     · BugCheckCallback, BugCheckReasonCallback, ShutDownCallback: use ListEntry
```
 
### 2.IoTImer
```
   Enum --> Travel IopTimerQueueHead
     Remove --> RemoveEntryList
     Start/Stop --> IoStartTimer(DeviceObject)/IoStopTimer(DeviceObject)
```   
### 3.DpcTimer
``` 
    Enum --> _Kprcb->TimerTable->TimerEntries(256)->travel list
    Remove --> KeCancelTimer(Timer)
 ```
 
### 4.SystemThread
```
    Enum --> Travel PspCidTable to get Object, just call the function write in Enum Process Thread
```

### 5.FilterDriver
```
    Enum --> First to get driverobject by name, then travel the driverobject's device stack and device chain.
    Remove --> change AttachedDevice
```

## KrnlHook
### 1.Get KeServiceDescriptorTable Address.
### 2.Get SSDT function address by function Index in SSDT.
### 3.Get KeServiceDescriptorTableShadow Address.
### 4.Get SSSDT function address by function Index in SSSDT.
### 5.Query KrnlFile's Import Functions and Export Functions.
```
(include travel IAT EAT, etc.)
```



