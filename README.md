# AltitudeSquatter

Minifilter altitude squatting tool for Windows x64. Displaces EDR/security minifilter drivers by placing legitimate drivers at their altitude positions.

## How it works

Windows minifilter drivers are loaded in order of their altitude value. Two drivers cannot occupy the same altitude. This tool sets legitimate boot-start drivers to the altitudes of security drivers. On reboot, the security filters find their altitude already taken.

## Supported targets

| Target | Minifilter | Altitude | Decoy |
|---|---|---|---|
| `defender` | WdFilter | 328010 | npsvctrig |
| `mssecflt` | MsSecFlt | 385600 | WIMMount |
| `sysmon` | SysmonDrv | 385201 | storqosflt |
| `crowdstrike` | csagent | 328010 | npsvctrig |
| `sentinelone` | SentinelMonitor | 385200 | CldFlt |
| `carbonblack` | CbDefenseFilter | 328000 | Wof |
| `sophos` | SophosED | 326000 | wcifs |
| `eset` | eamonm | 328000 | Wof |
| `kaspersky` | klif | 389800 | FileCrypt |
| `trendmicro` | TmFileEncDec | 385300 | bindflt |
| `elastic` | ElasticEndpoint | 385700 | luafv |
| `cortex` | CyveraK | 328010 | npsvctrig |
| `cylance` | CylanceDrv | 385100 | storqosflt |
| `malwarebytes` | MBAMSwissArmy | 385100 | storqosflt |

## Usage

```
AltitudeSquatter.exe list                    # Detect installed EDR minifilters
AltitudeSquatter.exe all                     # Squat all detected EDRs
AltitudeSquatter.exe defender                # Target Windows Defender only
AltitudeSquatter.exe defender sysmon         # Target multiple EDRs
AltitudeSquatter.exe crowdstrike             # Target CrowdStrike
AltitudeSquatter.exe restore                 # Restore all decoy drivers to defaults
AltitudeSquatter.exe restore defender        # Restore specific target
```

Requires **administrator privileges**. Reboot required for changes to take effect.

## Build

### Cross-compile from Linux (mingw-w64)

```bash
make
```

### Windows (MSVC Developer Command Prompt)

```cmd
cl /O2 main.c /Fe:AltitudeSquatter.exe advapi32.lib
```

## Disclaimer

This tool is provided for **authorized security testing and educational purposes only**. Use it only on systems you own or have explicit written permission to test. Unauthorized use against systems you do not own is illegal. The author assumes no liability for misuse.

## License

MIT — see [LICENSE](LICENSE)
