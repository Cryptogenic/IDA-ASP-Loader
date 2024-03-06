# IDA ASP Loader
Simple loader plugin for IDA to load AMD-SP or PSP firmware binaries. Will try to load bootloader blobs unpacked by [PSPTool](https://github.com/PSPReverse/PSPTool).

## Installation
Copy repo contents or script into `[ida root]/loaders`.

## Notes
- Load addresses are currently hardcoded as there's no easy way to dynamically deduce them. It's possible a given binary doesn't load at a correct address (open an issue)
- PSP files have some different magics, known ones are supported but there may be some binaries that have currently unsupported magics and won't be recognized (open an issue)

## License
This plugin is licensed under a [MIT](LICENSE) license.

## Resources
- [https://github.com/PSPReverse](https://github.com/PSPReverse)
- [https://doc.coreboot.org/soc/amd/psp_integration.html](https://doc.coreboot.org/soc/amd/psp_integration.html)
