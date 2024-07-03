# Malicious Service With Ntdll

## Educational purposes
I do not take responsibility for the misuse of the code in this repository. I created the project solely for educational purposes, seeking to better understand how certain real malwares are constructed and how they can be mitigated.

## Info
The project was programmed in C and consists of a service that utilizes advanced techniques to inject a Payload into its own process, specifically the Windows RuntimeBroker.exe.

Among the functions and techniques I used were:

NT Functions (SysCalls) - Using the SysWhispers3 tool, I can obtain the necessary SSN to operate any SysCall I choose. Consequently, I can avoid using Windows API functions that might be detectable by AVs.

ntdll Unhooking - Since I am using SysCalls, the code unhooks the .text section of ntdll.dll, allowing me to avoid potential hooks from security tools.

PPid Spoofing and DllPolicyBlock - These two techniques are implemented in the RuntimeBroker.exe process created by my service, avoiding suspicion on the PPid and preventing AVs and EDRs from loading .Dlls into the malicious process.

IsDebuggerPresent - I "recreated" the IsDebuggerPresent function, which uses the PEB structure to check for debuggers in the service process.

The chosen injection technique was APC (Asynchronous Procedure Call) injection, combined with the EarlyBird method, involving the creation of a target process for injection to occur on a specific thread. APC injection allows a thread to asynchronously execute a callback function on another thread within the same process.

As an addition, since the malware is a service, it can be installed on Windows with elevated permissions. However, this can result in gaining access to the System user and automatic startup of the service with the operating system, ensuring persistence.


## Usage
You need to make some changes to the code for it to work correctly, one of the changes is:

Change the ```#define PAYLOAD``` in the Functions.h file to the link that points to your Payload.

After doing this, execute the following commands with elevated permissions:
```bash
sc.exe create "Windows Update Scheduler" binpath= "Path\to\Windows Update Scheduler.exe start= auto"
```

```bash
net start "Windows Update Scheduler"
```

Done, now you are running the service! :)
