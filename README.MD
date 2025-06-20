# Windows PE Signature Thief
## If you find this project useful, please give a :star: to this repo

![GitHub top language](https://img.shields.io/github/languages/top/shawtyknowmyname/signature_thief)
![GitHub License](https://img.shields.io/github/license/shawtyknowmyname/signature_thief)
![GitHub Repo stars](https://img.shields.io/github/stars/shawtyknowmyname/signature_thief)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/shawtyknowmyname/signature_thief/total)
![GitHub Issues or Pull Requests](https://img.shields.io/github/issues/shawtyknowmyname/signature_thief)

## :pushpin: Description

Windows PE Signature Thief is a program designed to extract the digital signature from one PE file and install it onto another.

> :warning: **Disclaimer:**  
> The transferred signature is **cosmetic only**.  
> It will be **visibly present** in the file properties (e.g., Windows Explorer),  
> but **will not pass cryptographic verification** (e.g., `WinVerifyTrust`, `signtool`, etc.)  
> because the payload content does not match the original signed hash.

## :sparkles: Features

- Extracts the digital signature from a PE file.
- Installs the extracted signature onto another PE file.
- Supports command-line usage.

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

> The signature appended by this tool is not valid — and that’s the point.

It’s meant to explore **how far you can get** with just the appearance of trust, not the actual cryptographic proof of it.

**Use responsibly.**

## :books: References

- [Subverting Trust in Windows: Spoofing Code Signing (SpecterOps, 2022)](https://specterops.io/wp-content/uploads/sites/3/2022/06/SpecterOps_Subverting_Trust_in_Windows.pdf) — detailed research explaining how Windows trust mechanisms can be visually tricked using signature block reuse, which this project demonstrates.

## Special Thanks :hearts:

Big thanks to [annihilatorq](https://github.com/annihilatorq) for help and contributions!
