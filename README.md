# yihanko

LSPosed module for analyzing and bypassing Android root detection mechanisms.

## How it works

The module hooks common root detection APIs such as:
- File existence checks
- System property queries
- Runtime command execution

Hooks are applied at runtime using LSPosed without modifying the target APK.

## Requirements
- Rooted Android device
- LSPosed (Zygisk)
- Android 8.0+ (sdk26 ~ )
