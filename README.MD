# Windows PE Signature Thief
## If you find this project useful, please give a :star: to this repo

![GitHub top language](https://img.shields.io/github/languages/top/shawtyknowmyname/signature_thief)
![GitHub License](https://img.shields.io/github/license/shawtyknowmyname/signature_thief)
![GitHub Repo stars](https://img.shields.io/github/stars/shawtyknowmyname/signature_thief)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/shawtyknowmyname/signature_thief/total)
![GitHub Issues or Pull Requests](https://img.shields.io/github/issues/shawtyknowmyname/signature_thief)

## :pushpin: Description

Windows PE Signature Thief is a program designed to extract the digital signature from one PE file and install it onto another.

> ⚠️ **Disclaimer:**  
> The transferred signature is **cosmetic only**.  
> It will be **visibly present** in the file properties (e.g., Windows Explorer),  
> but **will not pass cryptographic verification** (e.g., `WinVerifyTrust`, `signtool`, etc.)  
> because the payload content does not match the original signed hash.

## :sparkles: Features

- Extracts the digital signature from a PE file.
- Installs the extracted signature onto another PE file.
- Supports command-line usage.
- :white_check_mark: **Works with both x86 (32‑bit) and x64 (64‑bit) PE binaries.**

## :file_folder: Installation
### Clone the repository:
```bash
git clone https://github.com/shawtyknowmyname/signature_thief.git
```
- Open the solution in Visual Studio or any preferred IDE.
- Build the project (Ensure that the build completes successfully).

## :rocket: Usage:
### Run the program.

- Enter the path of the signed file (from which you want to extract the signature).
- Enter the path of the payload file (where the signature should be applied).
- Specify the output path where the final signed file will be saved.

**Example of use:**
![](https://i.imgur.com/Su8VeiZ.jpeg)

---

# :computer: Using the command line:
1. **Open a command prompt and navigate to the directory containing the compiled program.**

2. **Run the command with the required arguments:**
```bash
signature_thief.exe <signed_file> <payload_file> <output_file>
```
- `<signed_file>`: Path to the signed file.
- `<payload_file>`: Path to the file that should receive the digital signature.
- `<output_file>`: Path to the final output file.

**Example of use:**
![](https://i.imgur.com/WE2P8Z5.png)

## :loudspeaker: Notes

- Ensure that both files are valid PE binaries (either 32‑bit or 64‑bit).
- If no valid signature is found, the program will throw an error.
- The modified file should be inspected manually to ensure proper signature block placement.
- The signature will **appear in the file**, but is **not valid** for security checks or software trust chains.

## Special Thanks :hearts:

Big thanks to [annihilatorq](https://github.com/annihilatorq) for help and contributions!
