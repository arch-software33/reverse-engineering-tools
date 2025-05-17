```markdown
# 🔍 Modern Reverse Engineering Resources

A curated collection of modern reverse engineering tools, techniques, and resources. This guide focuses on contemporary approaches to RE, including cloud-native applications, mobile platforms, and IoT devices.

## Contents
- [Binary Analysis](#binary-analysis)
- [Dynamic Analysis](#dynamic-analysis)
- [Mobile RE](#mobile-reverse-engineering)
- [Cloud & Container RE](#cloud-and-container-reverse-engineering)
- [Game Hacking](#game-hacking)
- [Hardware RE](#hardware-reverse-engineering)
- [Malware Analysis](#malware-analysis)

## Binary Analysis

### Modern Decompilers
- [Ghidra](https://ghidra-sre.org/) - NSA's software reverse engineering framework
- [Binary Ninja](https://binary.ninja/) - Interactive binary analysis platform
- [IDA Pro](https://hex-rays.com/ida-pro/) - Industry standard for complex binary analysis
- [JEB](https://www.pnfsoftware.com/) - Focus on mobile and native binaries
- [Cutter](https://cutter.re/) - Free reverse engineering platform powered by Rizin

### Symbolic/Concolic Execution
- [angr](https://angr.io/) - Python framework for analyzing binaries
- [Triton](https://triton.quarkslab.com/) - Dynamic binary analysis framework
- [Manticore](https://github.com/trailofbits/manticore) - Symbolic execution tool

### Modern Binary Formats
- WASM Analysis Tools
  - [wasm-decompiler](https://github.com/wwwg/wasmdec)
  - [wasm-tools](https://github.com/bytecodealliance/wasm-tools)
- Golang Binary Analysis
  - [go-reverse](https://github.com/sibears/go-reverse)
  - [redress](https://github.com/goretk/redress)

## Dynamic Analysis

### Modern Debuggers
- [GDB with GEF](https://github.com/hugsy/gef) - GDB Enhanced Features
- [x64dbg](https://x64dbg.com/) - Windows debugger with modern UI
- [Frida](https://frida.re/) - Dynamic instrumentation toolkit
- [LLDB](https://lldb.llvm.org/) - Next-gen debugger

### Runtime Analysis
- [DynamoRIO](https://dynamorio.org/) - Runtime code manipulation system
- [PIN](https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html) - Intel's dynamic binary instrumentation
- [Valgrind](https://valgrind.org/) - Instrumentation framework

## Mobile Reverse Engineering

### Android
- [jadx](https://github.com/skylot/jadx) - Modern Android decompiler
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile app security testing
- [Objection](https://github.com/sensepost/objection) - Runtime mobile exploration

### iOS
- [Hopper](https://www.hopperapp.com/) - Modern macOS/iOS reverse engineering
- [Clutch](https://github.com/KJCracks/Clutch) - iOS application dumper
- [Flexdecrypt](https://github.com/JohnCoates/flexdecrypt) - iOS decryption tool

## Cloud and Container Reverse Engineering

### Container Analysis
- [Dive](https://github.com/wagoodman/dive) - Docker image explorer
- [Clair](https://github.com/quay/clair) - Container vulnerability analysis
- [Trivy](https://github.com/aquasecurity/trivy) - Container security scanner

### Cloud Native RE
- [CloudMapper](https://github.com/duo-labs/cloudmapper) - AWS analysis
- [Prowler](https://github.com/prowler-cloud/prowler) - AWS security assessment
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) - K8s penetration testing

## Game Hacking

### Modern Game RE Tools
- [Cheat Engine](https://www.cheatengine.org/) - Memory scanner/debugger
- [ReClass.NET](https://github.com/ReClassNET/ReClass.NET) - Memory class rebuilder
- [GameOwl](https://gameowl.io/) - Game reverse engineering platform
- [HxD](https://mh-nexus.de/en/hxd/) - Modern hex editor

### Anti-Cheat Analysis
- [Process Hacker](https://processhacker.sourceforge.io/) - Advanced process analysis
- [ScyllaHide](https://github.com/x64dbg/ScyllaHide) - Anti-anti-debug tool

## Hardware Reverse Engineering

### Modern Hardware Tools
- [Ghidra's processor modules](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Processors)
- [Chipwhisperer](https://github.com/newaetech/chipwhisperer) - Hardware security analysis
- [JTAGulator](https://github.com/grandideastudio/jtagulator) - JTAG/UART discovery

### IoT Analysis
- [Binwalk](https://github.com/ReFirmLabs/binwalk) - Firmware analysis tool
- [FACT](https://github.com/fkie-cad/FACT_core) - Firmware analysis platform
- [Radare2](https://rada.re/n/radare2.html) - For embedded RE

## Malware Analysis

### Modern Analysis Platforms
- [CAPE](https://github.com/kevoreilly/CAPEv2) - Malware configuration extraction
- [YARA](https://virustotal.github.io/yara/) - Pattern matching for malware
- [Cuckoo Sandbox](https://cuckoosandbox.org/) - Automated analysis
- [ANY.RUN](https://any.run/) - Interactive malware analysis

### Threat Intelligence
- [MISP](https://www.misp-project.org/) - Threat intelligence platform
- [OpenCTI](https://www.opencti.io/) - Cyber threat intelligence

## Learning Resources

### Modern RE Learning Platforms
- [HackTheBox](https://www.hackthebox.eu/) - RE challenges
- [CrackMes.one](https://crackmes.one/) - RE challenges
- [Reverse Engineering on Medium](https://medium.com/tag/reverse-engineering)
- [Awesome Reversing](https://github.com/tylerha97/awesome-reversing)

### Communities
- [/r/ReverseEngineering](https://www.reddit.com/r/ReverseEngineering/)
- [REverse Engineering Stack Exchange](https://reverseengineering.stackexchange.com/)
- [Discord RE Server](https://discord.gg/reverse-engineering)

## Contributing

Feel free to submit a PR or create an issue to add more modern RE resources!

## License

MIT
```
