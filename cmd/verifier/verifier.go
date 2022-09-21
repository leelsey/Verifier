package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"golang.org/x/crypto/sha3"
	"io"
	"log"
	"os"
)

var (
	appver     = "0.2"
	lstdot     = " • "
	wrongUsage = lstdot + "Usage: verifier <command> <file_path> <verify_code>.\n" +
		lstdot + "It can use in <command> that one of Version, MD5, SHA1, " +
		"SHA224, SHA256, SHA384, SHA512, SHA512/224, SHA512/256, SHA3-224, SHA3-256, SHA3-384, SHA-512."
	wrongPath = lstdot + "Sorry, can't find the file or this is a directory"
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

func fileExists(absolutePath string) bool {
	info, err := os.Stat(absolutePath)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func Verifer(sumValue string) {
	var lstverify = lstdot + "Verify: "
	verifyCode := os.Args[3]
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
	checkSum := sha512.New512_256()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func sha3224Checker(absolutePath string) string {
	fileLoc, err := os.Open(absolutePath)
	if err != nil {
		log.Fatal(err)
	}
	checkSum := sha3.New224()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func sha3256Checker(absolutePath string) string {
	fileLoc, err := os.Open(absolutePath)
	if err != nil {
		log.Fatal(err)
	}
	checkSum := sha3.New256()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func sha3384Checker(absolutePath string) string {
	fileLoc, err := os.Open(absolutePath)
	if err != nil {
		log.Fatal(err)
	}
	checkSum := sha3.New384()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func sha3512Checker(absolutePath string) string {
	fileLoc, err := os.Open(absolutePath)
	if err != nil {
		log.Fatal(err)
	}
	checkSum := sha3.New512()
	if _, err := io.Copy(checkSum, fileLoc); err != nil {
		log.Fatal(err)
	}
	sumValue := fmt.Sprintf("%x", checkSum.Sum(nil))
	return sumValue
}

func md5MainAct() {
	var lstmd5 = lstdot + "MD5:"
	filePath := os.Args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstmd5, md5Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				fmt.Println(lstmd5, md5Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstmd5, md5Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				sumValue := md5Checker(absolutePath)
				fmt.Println(lstmd5, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				sumValue := md5Checker(absolutePath)
				fmt.Println(lstmd5, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := md5Checker(absolutePath)
			fmt.Println(lstmd5, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				sumValue := md5Checker(absolutePath)
				fmt.Println(lstmd5, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := md5Checker(absolutePath)
			fmt.Println(lstmd5, sumValue)
			Verifer(sumValue)
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha1MainAct() {
	var lstsha1 = lstdot + "SHA1:"
	filePath := os.Args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha1, sha1Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha1, sha1Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha1, sha1Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				sumValue := sha1Checker(absolutePath)
				fmt.Println(lstsha1, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				sumValue := sha1Checker(absolutePath)
				fmt.Println(lstsha1, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				sumValue := sha1Checker(absolutePath)
				fmt.Println(lstsha1, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha224MainAct() {
	var lstsha224 = lstdot + "SHA224:"
	filePath := os.Args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha224, sha224Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha224, sha224Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha224, sha224Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				sumValue := sha224Checker(absolutePath)
				fmt.Println(lstsha224, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				sumValue := sha224Checker(absolutePath)
				fmt.Println(lstsha224, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				sumValue := sha224Checker(absolutePath)
				fmt.Println(lstsha224, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha256MainAct() {
	var lstsha256 = lstdot + "SHA256:"
	filePath := os.Args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha256, sha256Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha256, sha256Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha256, sha256Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				sumValue := sha256Checker(absolutePath)
				fmt.Println(lstsha256, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha256Checker(absolutePath)
			fmt.Println(lstsha256, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				sumValue := sha256Checker(absolutePath)
				fmt.Println(lstsha256, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha256Checker(absolutePath)
			fmt.Println(lstsha256, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				sumValue := sha256Checker(absolutePath)
				fmt.Println(lstsha256, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha384MainAct() {
	var lstsha384 = lstdot + "SHA384:"
	filePath := os.Args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha384, sha384Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha384, sha384Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha384, sha384Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				sumValue := sha384Checker(absolutePath)
				fmt.Println(lstsha384, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha384Checker(absolutePath)
			fmt.Println(lstsha384, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				sumValue := sha384Checker(absolutePath)
				fmt.Println(lstsha384, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha384Checker(absolutePath)
			fmt.Println(lstsha384, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				sumValue := sha384Checker(absolutePath)
				fmt.Println(lstsha384, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha512MainAct() {
	var lstsha512 = lstdot + "SHA512:"
	filePath := os.Args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha512, sha512Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha512, sha512Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha512, sha512Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				sumValue := sha512Checker(absolutePath)
				fmt.Println(lstsha512, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha512Checker(absolutePath)
			fmt.Println(lstsha512, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				sumValue := sha512Checker(absolutePath)
				fmt.Println(lstsha512, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha512Checker(absolutePath)
			fmt.Println(lstsha512, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				sumValue := sha512Checker(absolutePath)
				fmt.Println(lstsha512, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha512224MainAct() {
	var lstsha512224 = lstdot + "SHA512/224:"
	filePath := os.Args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha512224, sha512224Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha512224, sha512224Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha512224, sha512224Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				sumValue := sha512224Checker(absolutePath)
				fmt.Println(lstsha512224, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha512224Checker(absolutePath)
			fmt.Println(lstsha512224, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				sumValue := sha512224Checker(absolutePath)
				fmt.Println(lstsha512224, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha512224Checker(absolutePath)
			fmt.Println(lstsha512224, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				sumValue := sha512224Checker(absolutePath)
				fmt.Println(lstsha512224, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha512256MainAct() {
	var lstsha512256 = lstdot + "SHA512/256:"
	filePath := os.Args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha512256, sha512256Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			fmt.Println(lstsha512256, sha512256Checker(absolutePath))
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha512256, sha512256Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			fmt.Println(lstsha512256, sha512256Checker(absolutePath))
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha512256, sha512256Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				sumValue := sha512256Checker(absolutePath)
				fmt.Println(lstsha512256, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha512256Checker(absolutePath)
			fmt.Println(lstsha512256, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				sumValue := sha512256Checker(absolutePath)
				fmt.Println(lstsha512256, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha512256Checker(absolutePath)
			fmt.Println(lstsha512256, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				sumValue := sha512256Checker(absolutePath)
				fmt.Println(lstsha512256, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha3224MainAct() {
	var lstsha3224 = lstdot + "SHA3-224:"
	filePath := os.Args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha3224, sha3224Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha3224, sha3224Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha3224, sha3224Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				sumValue := sha3224Checker(absolutePath)
				fmt.Println(lstsha3224, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha3224Checker(absolutePath)
			fmt.Println(lstsha3224, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				sumValue := sha3224Checker(absolutePath)
				fmt.Println(lstsha3224, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha3224Checker(absolutePath)
			fmt.Println(lstsha3224, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				sumValue := sha3224Checker(absolutePath)
				fmt.Println(lstsha3224, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha3256MainAct() {
	var lstsha3256 = lstdot + "SHA3-256:"
	filePath := os.Args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha3256, sha3256Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha3256, sha3256Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha3256, sha3256Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				sumValue := sha3256Checker(absolutePath)
				fmt.Println(lstsha3256, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha3256Checker(absolutePath)
			fmt.Println(lstsha3256, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				sumValue := sha3256Checker(absolutePath)
				fmt.Println(lstsha3256, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha3256Checker(absolutePath)
			fmt.Println(lstsha3256, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				sumValue := sha3256Checker(absolutePath)
				fmt.Println(lstsha3256, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha3384MainAct() {
	var lstsha3384 = lstdot + "SHA3-384:"
	filePath := os.Args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha3384, sha3384Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha3384, sha3384Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha3384, sha3384Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				sumValue := sha3384Checker(absolutePath)
				fmt.Println(lstsha3384, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha3384Checker(absolutePath)
			fmt.Println(lstsha3384, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				sumValue := sha3384Checker(absolutePath)
				fmt.Println(lstsha3384, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha3384Checker(absolutePath)
			fmt.Println(lstsha3384, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				sumValue := sha3384Checker(absolutePath)
				fmt.Println(lstsha3384, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func sha3512MainAct() {
	var lstsha3512 = lstdot + "SHA3-512:"
	filePath := os.Args[2]
	if len(os.Args) == 3 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha3512, sha3512Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha3512, sha3512Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				fmt.Println(lstsha3512, sha3512Checker(absolutePath))
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else if len(os.Args) == 4 {
		if filePath[0] == '/' {
			absolutePath := filePath
			if fileExists(absolutePath) == true {
				sumValue := sha3512Checker(absolutePath)
				fmt.Println(lstsha3512, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha3512Checker(absolutePath)
			fmt.Println(lstsha3512, sumValue)
			Verifer(sumValue)
		} else if filePath[0] == '~' {
			absolutePath := homeDir() + filePath[2:]
			if fileExists(absolutePath) == true {
				sumValue := sha3512Checker(absolutePath)
				fmt.Println(lstsha3512, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
			sumValue := sha3512Checker(absolutePath)
			fmt.Println(lstsha3512, sumValue)
			Verifer(sumValue)
		} else {
			absolutePath := workingDir() + filePath
			if fileExists(absolutePath) == true {
				sumValue := sha3512Checker(absolutePath)
				fmt.Println(lstsha3512, sumValue)
				Verifer(sumValue)
			} else if fileExists(absolutePath) == false {
				fmt.Println(wrongPath)
			}
		}
	} else {
		fmt.Println(wrongUsage)
	}
}

func main() {
	verOpt := flag.NewFlagSet("version", flag.ExitOnError)
	md5Opt := flag.NewFlagSet("md5", flag.ExitOnError)
	sha1Opt := flag.NewFlagSet("sha1", flag.ExitOnError)
	sha224Opt := flag.NewFlagSet("sha224", flag.ExitOnError)
	sha256Opt := flag.NewFlagSet("sha256", flag.ExitOnError)
	sha384Opt := flag.NewFlagSet("sha384", flag.ExitOnError)
	sha512Opt := flag.NewFlagSet("sha512", flag.ExitOnError)
	sha512224Opt := flag.NewFlagSet("sha512224", flag.ExitOnError)
	sha512256Opt := flag.NewFlagSet("sha512256", flag.ExitOnError)
	sha3224Opt := flag.NewFlagSet("sha3224", flag.ExitOnError)
	sha3256Opt := flag.NewFlagSet("sha3256", flag.ExitOnError)
	sha3384Opt := flag.NewFlagSet("sha3384", flag.ExitOnError)
	sha3512Opt := flag.NewFlagSet("sha3512", flag.ExitOnError)
	if len(os.Args) == 1 {
		fmt.Println(wrongUsage)
	} else {
		switch os.Args[1] {
		case "version", "Version", "ver", "Ver", "v", "V", "-v", "-ver", "-version", "--v", "--Ver", "--Version":
			err := verOpt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			fmt.Println(lstdot + "Version: " + appver)
		case "md5", "MD5", "5":
			err := md5Opt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			md5MainAct()
		case "sha1", "sha", "SHA1", "SHA", "1":
			err := sha1Opt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			sha1MainAct()
		case "sha224", "SHA224", "224":
			err := sha224Opt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			sha224MainAct()
		case "sha256", "SHA256", "256":
			err := sha256Opt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			sha256MainAct()
		case "sha384", "SHA384", "384":
			err := sha384Opt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			sha384MainAct()
		case "sha512", "SHA512", "512":
			err := sha512Opt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			sha512MainAct()
		case "sha512224", "sha512/224", "SHA512224", "SHA512/224", "512224", "512/224":
			err := sha512224Opt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			sha512224MainAct()
		case "sha512256", "sha512/256", "SHA512256", "SHA512/256", "512256", "512/256":
			err := sha512256Opt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			sha512256MainAct()
		case "sha3224", "sha3-224", "SHA3224", "SHA3-224", "3224", "3-224":
			err := sha3224Opt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			sha3224MainAct()
		case "sha3256", "sha3-256", "SHA3256", "SHA3-256", "3256", "3-256":
			err := sha3256Opt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			sha3256MainAct()
		case "sha3384", "sha3-384", "SHA3384", "SHA3-384", "3384", "3-384":
			err := sha3384Opt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			sha3384MainAct()
		case "sha3512", "sha3-512", "SHA3512", "SHA3-512", "3512", "3-512":
			err := sha3512Opt.Parse(os.Args[1:])
			if err != nil {
				return
			}
			sha3512MainAct()
		default:
			fmt.Println(wrongUsage)
		}
	}
}
