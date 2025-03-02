# Windows PE Signature Thief

![GitHub top language](https://img.shields.io/github/languages/top/shawtyknowmyname/signature_thief)
![GitHub License](https://img.shields.io/github/license/shawtyknowmyname/signature_thief)
![GitHub Repo stars](https://img.shields.io/github/stars/shawtyknowmyname/signature_thief)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/shawtyknowmyname/signature_thief/total)
![GitHub Issues or Pull Requests](https://img.shields.io/github/issues/shawtyknowmyname/signature_thief) 

## :pushpin: Description

Windows PE Signature Thief is a program designed to extract the digital signature from one PE file and install it onto another.

## :sparkles: Features

- Extracts the digital signature from a PE file.

- Installs the extracted signature onto another PE file.

- Supports command-line usage for automation.

:no_entry_sign: Does not support x86 (32-bit) executables! Only x64 PE files are supported.

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

Ensure that both files are PE x64 binaries.

If no valid signature is found, the program will throw an error.

The modified file should be inspected manually to ensure proper signing.

## Special Thanks :hearts:

Big thanks to [annihilatorq](https://github.com/annihilatorq) for help and contributions!

## If you find this project useful, please :star: the repo to show your support! :raised_hands:

