package filecrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
)

const (
	credentialFile = ".filecrypt"
	envPassword    = "FILECRYPT_PASSWORD"
)

// GenKey generates a hash
func GenKey() {
	plaintext := getPasswordFromInput()
	er1 := writeEncryptionKey(plaintext)
	errCheck("FATAL", "%v", er1)
	filePath := fmt.Sprintf("%v.key", getCredentialsFilePath())
	fmt.Printf("SUCCESS: Encrypted credentials file created on: '%v'\n", filePath)
	os.Exit(0)
}

// Encrypt will encrypt a given filen with a 16, 24 or 32 bytes long key
// to select between AES-128, AES-192 or AES-256.
func Encrypt() {
	plaintext := getPasswordFromInput()
	passphrase := sha256.Sum256(plaintext)
	// filePath := fmt.Sprintf("%v.key", getCredentialsFilePath())
	filePath := "/home/silveiralexf/go/src/github.com/silveiralexf/gocrypto/file.txt"
	err := encryptFile(passphrase[:], filePath)
	errCheck("FATAL", "Failed to encrypt file", err)
}

func encryptFile(key []byte, filePath string) error {
	plaintext, er1 := ioutil.ReadFile(filepath.Clean(filePath))
	errCheck("FATAL", "Failed reading key. Exiting!", er1)

	f, er2 := os.Create(filePath)
	errCheck("FATAL", "Failed creating encrypted file. Exiting!", er2)

	// Write the original plaintext size into the output file first, encoded in
	// a 8-byte integer.
	origSize := uint64(len(plaintext))

	er3 := binary.Write(f, binary.LittleEndian, origSize)
	errCheck("FATAL", "Failed writing encrypted file. Exiting!", er3)

	// Pad plaintext to a multiple of BlockSize with random padding
	if len(plaintext)%aes.BlockSize != 0 {
		bytesToPad := aes.BlockSize - (len(plaintext) % aes.BlockSize)
		padding := make([]byte, bytesToPad)

		_, er4 := rand.Read(padding)
		errCheck("FATAL", "Failed generating random number. Exiting!", er4)

		plaintext = append(plaintext, padding...)
	}

	// Generate random IV and write it to the output file.
	iv := make([]byte, aes.BlockSize)
	_, er5 := rand.Read(iv)
	errCheck("FATAL", "Failed reading random IV. Exiting!", er5)

	_, er6 := f.Write(iv)
	errCheck("FATAL", "Failed writing random IV. Exiting!", er6)

	// Ciphertext has the same size as the padded plaintext.
	ciphertext := make([]byte, len(plaintext))

	// Use AES implementation of the cipher.Block interface to encrypt the whole
	// file in CBC mode.
	block, er7 := aes.NewCipher(key)
	errCheck("FATAL", "Failed to block cipher the file with provided key. Exiting!", er7)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	_, er8 := f.Write(ciphertext)
	errCheck("FATAL", "Failed writing encrypted file. Exiting!", er8)

	return f.Close()
}

// DecryptFile returns decrypted content of a file as a variable or saves its
// content into a file depending on 'saveLocally' being set to true or false
func DecryptFile(key []byte, filePath string, saveLocally bool) []byte {

	ciphertext, er1 := ioutil.ReadFile(filepath.Clean(filePath))
	errCheck("FATAL", "Could not find target file. Exiting!", er1)

	// cipertext has the original plaintext size in the first 8 bytes, then IV
	// in the next 16 bytes, then the actual ciphertext in the rest of the buffer.
	// Read the original plaintext size, and the IV.
	var origSize uint64
	buf := bytes.NewReader(ciphertext)

	er3 := binary.Read(buf, binary.LittleEndian, &origSize)
	errCheck("FATAL", "", er3)

	iv := make([]byte, aes.BlockSize)

	_, er4 := buf.Read(iv)
	errCheck("FATAL", "", er4)

	// The remaining ciphertext has size=paddedSize.
	paddedSize := len(ciphertext) - 8 - aes.BlockSize
	if paddedSize%aes.BlockSize != 0 {
		errCheck("FATAL", "want padded plaintext size to be aligned to block size", nil)
	}
	plaintext := make([]byte, paddedSize)
	block, er5 := aes.NewCipher(key)
	errCheck("FATAL", "", er5)

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext[8+aes.BlockSize:])

	if saveLocally {
		f, er1 := os.Create(filePath + ".dec")
		errCheck("FATAL", "Failed ", er1)

		_, er2 := f.Write(plaintext[:origSize])
		errCheck("FATAL", "", er2)

		errCheck("INFO", fmt.Sprintf("File successfully decrypted on '%v.dec'", filePath), nil)

		er3 := f.Close()
		errCheck("FATAL", "Failed to close file", er3)
	}
	return plaintext[:origSize]
}

// getPasswordFromInput will retrieve password from command line input
func getPasswordFromInput() []byte {
	password := os.Getenv(envPassword)
	if password == "" {
		fmt.Printf(">> Enter a passphrase for your local credentials:\n")

		_, er1 := fmt.Scan(&password)
		errCheck("FATAL", "Failed to retrieve input provided. Exiting!", er1)
	}
	return []byte(password)
}

// GetCredentialsFilePath returns the file path for the credentials file
// which by default is $HOME/.sync
func getCredentialsFilePath() string {
	username, err := user.Current()
	errCheck("FATAL", "Could not determine user home directory", err)
	filePath := username.HomeDir + "/" + credentialFile
	return filePath
}

// writeEncryptionKey generates a hash key from password provided by user at '$HOME/.slyncd.key'
func writeEncryptionKey(passphrase []byte) error {
	hash, er1 := hashPass(passphrase)
	errCheck("FATAL", "Failed to generate a credential key. Exiting!", er1)

	filePath := fmt.Sprintf("%v.key", getCredentialsFilePath())
	f, er2 := os.Create(filePath)
	errCheck("FATAL", "Failed creating credential key. Exiting!", er2)

	_, er3 := f.Write(hash)
	errCheck("FATAL", "Failed writing credential key content. Exiting!", er3)
	return nil
}

// hashPass will take a plaintext password and return a []byte hash)
func hashPass(password []byte) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword(password, 10)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func errCheck(severity, msg string, err error) {
	output := fmt.Sprintf("%v - %v %v", severity, msg, err)
	if err != nil && severity == "FATAL" {
		fmt.Println(output)
		os.Exit(1)
	} else if err != nil {
		fmt.Println(output)
	}

}
