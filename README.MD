# Windows PE Signature Thief
## If you find this project useful, please give a :star: to this repo

![GitHub top language](https://img.shields.io/github/languages/top/shawtyknowmyname/signature_thief)
![GitHub License](https://img.shields.io/github/license/shawtyknowmyname/signature_thief)
![GitHub Repo stars](https://img.shields.io/github/stars/shawtyknowmyname/signature_thief)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/shawtyknowmyname/signature_thief/total)
![GitHub Issues or Pull Requests](https://img.shields.io/github/issues/shawtyknowmyname/signature_thief)

## :pushpin: Description

Windows PE Signature Thief is a program designed to extract the digital signature from one PE file and apply it onto another.

> :warning: **Disclaimer:**  
> The transferred signature is **cosmetic only**.  
> It will be **visibly present** in the file properties (e.g., Windows Explorer),  
> but **will not pass cryptographic verification** (e.g., `WinVerifyTrust`, `signtool`, etc.)  
> because the payload content does not match the original signed hash.

## :sparkles: Features

- Extracts the digital signature from a signed PE file (32-bit and 64-bit).
- Applies the extracted signature onto another PE file.
- Supports both interactive and command-line usage.

## :wrench: Requirements

- **Windows** (uses WinAPI PE structures)
- **C++23** compatible compiler (MSVC v143+ with `/std:c++latest`)
- **Visual Studio 2022** or later

## :file_folder: Project Structure

```
signature_thief/
  main.cpp                 # Entry point, CLI / interactive input
  signature_thief.hpp      # signature_thief class interface
  signature_thief.cpp      # Certificate extraction, application, saving
  pe_utils.hpp             # PE parsing utilities (namespace pe_utils)
  pe_utils.cpp             # Binary file I/O, security directory lookup
```

| Module | Responsibility |
|---|---|
| `pe_utils` | Low-level PE parsing: DOS/NT header validation, security directory access, binary file reading, alignment |
| `signature_thief` | Business logic: loads payload, extracts certificate from donor, applies it, saves result |
| `main` | User interaction: CLI arguments or interactive prompts |

## :file_folder: Installation

### Clone the repository:
```bash
git clone https://github.com/shawtyknowmyname/signature_thief.git
```
- Open `signature_thief.sln` in Visual Studio.
- Ensure C++ Language Standard is set to `/std:c++latest` (Project Properties → C/C++ → Language).
- Build the project.

## :rocket: Usage

### Interactive mode

Run the program without arguments and follow the prompts:
- Enter the path of the signed file (from which you want to extract the signature).
- Enter the path of the payload file (where the signature should be applied).
- Specify the output path where the final signed file will be saved.

**Example of use:**
![](https://i.imgur.com/Su8VeiZ.jpeg)

### Command-line mode

```bash
signature_thief.exe <signed_file> <payload_file> <output_file>
```
- `<signed_file>` — path to the PE file that contains the digital signature.
- `<payload_file>` — path to the PE file that should receive the signature.
- `<output_file>` — path where the resulting file will be saved.

**Example of use:**
![](https://i.imgur.com/WE2P8Z5.png)

## :loudspeaker: Notes

- Both files must be valid PE binaries (32-bit or 64-bit).
- If no valid signature is found in the donor file, the program will report an error.
- The signature will **appear in the file**, but is **not valid** for security checks or software trust chains.
- :warning: **Note:** This tool has **not been tested on 32-bit Windows systems**. Compatibility with 32-bit OS environments is not guaranteed.

## :warning: Why this project matters

Over the years, researchers have observed that different Anti-Virus and security products treat PE signatures inconsistently:

- Some AVs **do not validate** the digital signature cryptographically — they simply check for the **presence of a certificate block** in the PE header.
- Others give **implicit trust** to specific certificate authorities (e.g., Microsoft, Adobe) **without verifying** if the signature is still valid.
- A few rely solely on the fact that a `Certificate Table` exists and is non-zero — ignoring whether it matches the binary content.

This leads to scenarios where a PE file with an **invalid or spoofed signature** may appear **less suspicious** or may even **bypass basic static detection heuristics**.

The purpose of this project is to **demonstrate and highlight** these inconsistencies in trust mechanisms, allowing researchers to:

- Evaluate which AV engines rely on the **presence** versus the **validity** of a signature.
- Understand which certificate authorities are implicitly "whitelisted" by vendors.
- Reproduce conditions described in security papers such as [SpecterOps: Subverting Trust in Windows](https://specterops.io/wp-content/uploads/sites/3/2022/06/SpecterOps_Subverting_Trust_in_Windows.pdf).

> The signature appended by this tool is not valid — and that's the point.

It's meant to explore **how far you can get** with just the appearance of trust, not the actual cryptographic proof of it.

**Use responsibly.**

## :books: References

- [Subverting Trust in Windows: Spoofing Code Signing (SpecterOps, 2022)](https://specterops.io/wp-content/uploads/sites/3/2022/06/SpecterOps_Subverting_Trust_in_Windows.pdf) — detailed research explaining how Windows trust mechanisms can be visually tricked using signature block reuse, which this project demonstrates.

## Special Thanks :hearts:

Big thanks to [annihilatorq](https://github.com/annihilatorq) for help and contributions!
