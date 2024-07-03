#include <stdio.h>
#include <windows.h>

#include "Service.h"

#pragma warning (disable:4996)

int main() {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    if (StartServiceCtrlDispatcher(ServiceTable) == 0) {
        return -1;
    }

    return 0;
}
