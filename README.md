# Verifier

### Checksum hash value and check verification

## Support OS
- macOS
- Linux
- Windows
- FreeBSD

## 2. How to use it?
This is CLI tool.
### 1) Output checksum
```bash
verifier <command> <file_path>
```
### 2) Verify hash value
```bash
verifier <command> <file_path> <verification_code>
```
### Command list
- Version
- MD5
- SHA1
- SHA224
- SHA256
- SHA384
- SHA512
- SHA512/224
- SHA512/256
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512

## 3. How to own build?
Before this, need Git and Go language
```bash
git clone https://github.com/leelsey/Verifier
cd Verifier/cmd/verifier && go mod tidy
go build verifier.go
```
