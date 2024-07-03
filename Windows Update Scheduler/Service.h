#pragma once
#include <stdio.h>
#include <windows.h>
#include "Functions.h"

#define SERVICE_NAME  "Windows Update Scheduler"

void ServiceMain(int argc, char** argv);

void ControlHandler(DWORD request);