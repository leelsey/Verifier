package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

var (
	appver     = "0.1"
	lstdot     = " • "
	args       = os.Args
	wrongUsage = lstdot + "Usage: verifier <command> <file_path> <verify_code>.\n" +
		lstdot + "It can use in <command> that one of Version, MD5, SHA1, " +
		"SHA224, SHA256, SHA384, SHA512, SHA512/224, SHA512/256, SHA3-224, SHA3-256, SHA3-384, SHA-512."
	lstverify    = lstdot + "Verify: "
	lstmd5       = lstdot + "MD5:"
	lstsha1      = lstdot + "SHA1:"
	lstsha224    = lstdot + "SHA224:"
	lstsha256    = lstdot + "SHA256:"
	lstsha384    = lstdot + "SHA384:"
	lstsha512    = lstdot + "SHA512:"
	lstsha512224 = lstdot + "SHA512/224:"
	lstsha512256 = lstdot + "SHA512/256:"
	lstsha3224   = lstdot + "SHA3-224:"
	lstsha3256   = lstdot + "SHA3-256:"
	lstsha3384   = lstdot + "SHA3-384:"
	lstsha3512   = lstdot + "SHA3-512:"
)

func homeDir() string {
	homedirpath, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	return homedirpath + "/"
}

func workingDir() string {
	pwdir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	return pwdir + "/"
}

func Verifer(sumValue string) {
	verifyCode := args[3]
	if verifyCode == sumValue {
		fmt.Println(lstverify + "Correct")
	} else {
		fmt.Println(lstverify + "Incorrect")
	}
}

func md5Checker(absolutePath string) string {
	fileLoc, err := os.Open(absolutePath)
	if err != nil {
		log.Fatal(err)
	}
	//defer fileLoc.Close()
	checkSum := md5.New()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func sha1Checker(absolutePath string) string {
	fileLoc, err := os.Open(absolutePath)
	if err != nil {
		log.Fatal(err)
	}
	//defer fileLoc.Close()
	checkSum := sha1.New()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func sha224Checker(absolutePath string) string {
	fileLoc, err := os.Open(absolutePath)
	if err != nil {
		log.Fatal(err)
	}
	//defer fileLoc.Close()
	checkSum := sha256.New224()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func sha256Checker(absolutePath string) string {
	fileLoc, err := os.Open(absolutePath)
	if err != nil {
		log.Fatal(err)
	}
	//defer fileLoc.Close()
	checkSum := sha256.New()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func sha384Checker(absolutePath string) string {
	fileLoc, err := os.Open(absolutePath)
	if err != nil {
		log.Fatal(err)
	}
	//defer fileLoc.Close()
	checkSum := sha512.New384()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func sha512Checker(absolutePath string) string {
	fileLoc, err := os.Open(absolutePath)
	if err != nil {
		log.Fatal(err)
	}
	//defer fileLoc.Close()
	checkSum := sha512.New()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func sha512224Checker(absolutePath string) string {
	fileLoc, err := os.Open(absolutePath)
	if err != nil {
		log.Fatal(err)
	}
	//defer fileLoc.Close()
	checkSum := sha512.New512_224()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func sha512256Checker(absolutePath string) string {
	fileLoc, err := os.Open(absolutePath)
	if err != nil {
		log.Fatal(err)
	}
	//defer fileLoc.Close()
	checkSum := sha512.New512_256()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func sha3224Checker(absolutePath string) string {
	return wrongUsage
}

func sha3256Checker(absolutePath string) string {
	return wrongUsage
}

func sha3384Checker(absolutePath string) string {
	return wrongUsage
}

func sha3512Checker(absolutePath string) string {
	return wrongUsage
}

func md5MainAct() {
	filePath := args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			fmt.Println(lstmd5, md5Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			fmt.Println(lstmd5, md5Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			fmt.Println(lstmd5, md5Checker(absolutePath))
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			sumValue := md5Checker(absolutePath)
			fmt.Println(lstmd5, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			sumValue := md5Checker(absolutePath)
			fmt.Println(lstmd5, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			sumValue := md5Checker(absolutePath)
			fmt.Println(lstmd5, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha1MainAct() {
	filePath := args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			fmt.Println(lstsha1, sha1Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			fmt.Println(lstsha1, sha1Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			fmt.Println(lstsha1, sha1Checker(absolutePath))
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			sumValue := sha1Checker(absolutePath)
			fmt.Println(lstsha1, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			sumValue := sha1Checker(absolutePath)
			fmt.Println(lstsha1, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			sumValue := sha1Checker(absolutePath)
			fmt.Println(lstsha1, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha224MainAct() {
	filePath := args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			fmt.Println(lstsha224, sha224Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			fmt.Println(lstsha224, sha224Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			fmt.Println(lstsha224, sha224Checker(absolutePath))
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			sumValue := sha224Checker(absolutePath)
			fmt.Println(lstdot+"MD5:", sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			sumValue := sha224Checker(absolutePath)
			fmt.Println(lstsha224, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			sumValue := sha224Checker(absolutePath)
			fmt.Println(lstsha224, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha256MainAct() {
	filePath := args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			fmt.Println(lstsha256, sha256Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			fmt.Println(lstsha256, sha256Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			fmt.Println(lstsha256, sha256Checker(absolutePath))
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			sumValue := sha256Checker(absolutePath)
			fmt.Println(lstsha256, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			sumValue := sha256Checker(absolutePath)
			fmt.Println(lstsha256, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			sumValue := sha256Checker(absolutePath)
			fmt.Println(lstsha256, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha384MainAct() {
	filePath := args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			fmt.Println(lstsha384, sha384Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			fmt.Println(lstsha384, sha384Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			fmt.Println(lstsha384, sha384Checker(absolutePath))
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			sumValue := sha384Checker(absolutePath)
			fmt.Println(lstsha384, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			sumValue := sha384Checker(absolutePath)
			fmt.Println(lstsha384, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			sumValue := sha384Checker(absolutePath)
			fmt.Println(lstsha384, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha512MainAct() {
	filePath := args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			fmt.Println(lstsha512, sha512Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			fmt.Println(lstsha512, sha512Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			fmt.Println(lstsha512, sha512Checker(absolutePath))
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			sumValue := sha512Checker(absolutePath)
			fmt.Println(lstsha512, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			sumValue := sha512Checker(absolutePath)
			fmt.Println(lstsha512, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			sumValue := sha512Checker(absolutePath)
			fmt.Println(lstsha512, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha512224MainAct() {
	filePath := args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			fmt.Println(lstsha512224, sha512224Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			fmt.Println(lstsha512224, sha512224Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			fmt.Println(lstsha512224, sha512224Checker(absolutePath))
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			sumValue := sha512224Checker(absolutePath)
			fmt.Println(lstsha512224, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			sumValue := sha512224Checker(absolutePath)
			fmt.Println(lstsha512224, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			sumValue := sha512224Checker(absolutePath)
			fmt.Println(lstsha512224, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha512256MainAct() {
	filePath := args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			fmt.Println(lstsha512256, sha512256Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			fmt.Println(lstsha512256, sha512256Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			fmt.Println(lstsha512256, sha512256Checker(absolutePath))
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			sumValue := sha512256Checker(absolutePath)
			fmt.Println(lstsha512256, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			sumValue := sha512256Checker(absolutePath)
			fmt.Println(lstsha512256, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			sumValue := sha512256Checker(absolutePath)
			fmt.Println(lstsha512256, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha3224MainAct() {
	filePath := args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			fmt.Println(lstsha3224, sha3224Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			fmt.Println(lstsha3224, sha3224Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			fmt.Println(lstsha3224, sha3224Checker(absolutePath))
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			sumValue := sha3224Checker(absolutePath)
			fmt.Println(lstsha3224, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			sumValue := sha3224Checker(absolutePath)
			fmt.Println(lstsha3224, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			sumValue := sha3224Checker(absolutePath)
			fmt.Println(lstsha3224, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha3256MainAct() {
	filePath := args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			fmt.Println(lstsha3256, sha3256Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			fmt.Println(lstsha3256, sha3256Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			fmt.Println(lstsha3256, sha3256Checker(absolutePath))
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			sumValue := sha3256Checker(absolutePath)
			fmt.Println(lstsha3256, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			sumValue := sha3256Checker(absolutePath)
			fmt.Println(lstsha3256, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			sumValue := sha3256Checker(absolutePath)
			fmt.Println(lstsha3256, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha3384MainAct() {
	filePath := args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			fmt.Println(lstsha3384, sha3384Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			fmt.Println(lstsha3384, sha3384Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			fmt.Println(lstsha3384, sha3384Checker(absolutePath))
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			sumValue := sha3384Checker(absolutePath)
			fmt.Println(lstsha3384, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			sumValue := sha3384Checker(absolutePath)
			fmt.Println(lstsha3384, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			sumValue := sha3384Checker(absolutePath)
			fmt.Println(lstsha3384, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha3512MainAct() {
	filePath := args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			fmt.Println(lstsha3512, sha3512Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			fmt.Println(lstsha3512, sha3512Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			fmt.Println(lstsha3512, sha3512Checker(absolutePath))
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			sumValue := sha3512Checker(absolutePath)
			fmt.Println(lstsha3512, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			sumValue := sha3512Checker(absolutePath)
			fmt.Println(lstsha3512, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			sumValue := sha3512Checker(absolutePath)
			fmt.Println(lstsha3512, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func main() {
	ver_Opt := flag.NewFlagSet("version", flag.ExitOnError)
	md5_Opt := flag.NewFlagSet("md5", flag.ExitOnError)
	sha1_Opt := flag.NewFlagSet("sha1", flag.ExitOnError)
	sha2_224_Opt := flag.NewFlagSet("sha224", flag.ExitOnError)
	sha2_256_Opt := flag.NewFlagSet("sha256", flag.ExitOnError)
	sha2_384_Opt := flag.NewFlagSet("sha384", flag.ExitOnError)
	sha2_512_Opt := flag.NewFlagSet("sha512", flag.ExitOnError)
	sha2_512224_Opt := flag.NewFlagSet("sha512224", flag.ExitOnError)
	sha2_512256_Opt := flag.NewFlagSet("sha512256", flag.ExitOnError)
	sha3_224_Opt := flag.NewFlagSet("sha3224", flag.ExitOnError)
	sha3_256_Opt := flag.NewFlagSet("sha3256", flag.ExitOnError)
	sha3_384_Opt := flag.NewFlagSet("sha3384", flag.ExitOnError)
	sha3_512_Opt := flag.NewFlagSet("sha3512", flag.ExitOnError)
	if len(os.Args) == 1 {
		fmt.Println(wrongUsage)
	} else {
		switch os.Args[1] {
		case "version", "Version", "ver", "Ver", "v", "V", "-v", "-ver", "-version", "--v", "--Ver", "--Version":
			ver_Opt.Parse(os.Args[1:])
			fmt.Println(lstdot + "Version: " + appver)
		case "md5", "MD5", "5":
			md5_Opt.Parse(os.Args[1:])
			md5MainAct()
		case "sha1", "sha", "SHA1", "SHA", "1":
			sha1_Opt.Parse(os.Args[1:])
			sha1MainAct()
		case "sha224", "SHA224", "224":
			sha2_224_Opt.Parse(os.Args[1:])
			sha224MainAct()
		case "sha256", "SHA256", "256":
			sha2_256_Opt.Parse(os.Args[1:])
			sha256MainAct()
		case "sha384", "SHA384", "384":
			sha2_384_Opt.Parse(os.Args[1:])
			sha384MainAct()
		case "sha512", "SHA512", "512":
			sha2_512_Opt.Parse(os.Args[1:])
			sha512MainAct()
		case "sha512224", "sha512/224", "SHA512224", "SHA512/224", "512224", "512/224":
			sha2_512224_Opt.Parse(os.Args[1:])
			sha512224MainAct()
		case "sha512256", "sha512/256", "SHA512256", "SHA512/256", "512256", "512/256":
			sha2_512256_Opt.Parse(os.Args[1:])
			sha512256MainAct()
		case "sha3224", "sha3-224", "SHA3224", "SHA3-224", "3224", "3-224":
			sha3_224_Opt.Parse(os.Args[1:])
			sha3224MainAct()
		case "sha3256", "sha3-256", "SHA3256", "SHA3-256", "3256", "3-256":
			sha3_256_Opt.Parse(os.Args[1:])
			sha3256MainAct()
		case "sha3384", "sha3-384", "SHA3384", "SHA3-384", "3384", "3-384":
			sha3_384_Opt.Parse(os.Args[1:])
			sha3384MainAct()
		case "sha3512", "sha3-512", "SHA3512", "SHA3-512", "3512", "3-512":
			sha3_512_Opt.Parse(os.Args[1:])
			sha3512MainAct()
		default:
			fmt.Println(wrongUsage)
		}
	}
}
