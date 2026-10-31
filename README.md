# AltitudeSquatter

Minifilter altitude squatting tool for Windows x64. Displaces security minifilter drivers (WdFilter, MsSecFlt) by placing legitimate drivers at their altitude positions.

## How it works

Windows minifilter drivers are loaded in order of their altitude value. Two drivers cannot occupy the same altitude. This tool sets legitimate boot-start drivers (WIMMount, npsvctrig) to the altitudes of security drivers:

| Decoy driver | Target altitude | Displaced driver |
|---|---|---|
| WIMMount | 385600 | MsSecFlt |
| npsvctrig | 328010 | WdFilter |

Each decoy also gets `Start=0` (boot) and `Group=FSFilter Bottom` to ensure it loads before the security driver. On reboot, the security filters find their altitude already taken.

## Usage

```
AltitudeSquatter.exe
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
