package main

import (
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"google.golang.org/api/option"

	"cloud.google.com/go/storage"
	"github.com/illicitonion/cloudbackup/crypto"
	"github.com/illicitonion/cloudbackup/files"
	"github.com/illicitonion/cloudbackup/fscache"
	"github.com/illicitonion/cloudbackup/gcs"
	"github.com/illicitonion/cloudbackup/meta"
)

const keySize = 32

func main() {
	keyFile := flag.String("key-file", "", "PEM-encoded file containing Encryption, Authentication, and IV keys")

	var command string
	if len(os.Args) < 2 || os.Args[1][0] == '-' {
		log.Fatalf("Need to specify subcommand. Usage: %s [encrypt|decrypt|keygen]", os.Args[0])
	}
	command = os.Args[1]
	if command != "encrypt" && command != "decrypt" && command != "keygen" {
		log.Fatal("Subcommand must be one of encrypt, decrypt, or keygen, got ", command)
	}
	os.Args = append([]string{os.Args[0] + " " + os.Args[1]}, os.Args[2:]...)

	var metaFile, chunkSpec, file, excludeNamesFlag *string
	var chunkBytes *int
	if command != "keygen" {
		metaFile = flag.String("meta-file", "", "boltdb file for metadata")
		chunkSpec = flag.String("chunkspec", "", "Spec of where to save chunks. Valid values: local:/path/to/local/directory, gcs:path-to-json-keyfile:bucket-name")
		file = flag.String("file", "", "File or directory to encrypt/decrypt; -file=. will encrypt the whole current working directory (recursively), or decrypt all known files.")

		if command == "encrypt" {
			chunkBytes = flag.Int("chunk-bytes", -1, "Number of bytes of plaintext per encrypted chunk")
			excludeNamesFlag = flag.String("exclude-names", "", "File or directory names to ignore; semicolon-delimited")
		}
	}

	flag.Parse()

	if *keyFile == "" {
		fatal("Need to specify --key-file", true)
	}

	if command == "keygen" {
		generateKeys(*keyFile)
		return
	}

	if filepath.IsAbs(*file) {
		fatal("--file must be a relative file", true)
	}

	keyBytes, err := ioutil.ReadFile(*keyFile)
	if err != nil {
		log.Fatal("Error reading key file: ", err)
	}
	keys := crypto.ReadKeys(keyBytes)
	aesKey := keys["Encryption"]
	hmacKey := keys["Authentication"]
	ivKey := keys["IV"]
	if len(aesKey) != keySize || len(hmacKey) != keySize || len(ivKey) != keySize {
		fatal("Bad keys: Want each to be 256 bits", false)
	}

	chunkStore, err := parseChunkSpec(*chunkSpec, keys)
	if err != nil {
		log.Fatal("Error parsing chunk spec: ", err)
	}

	if *metaFile == "" {
		log.Fatal("Must set --meta-file")
	}
	db, err := meta.NewDB(*metaFile)
	if err != nil {
		log.Fatalf("Error opening database at %v: %v", *metaFile, err)
	}
	defer db.Close()

	switch command {
	case "encrypt":
		if *chunkBytes <= 0 {
			fatal(fmt.Sprintf("Need chunk-bytes greater than zero, got %v", *chunkBytes), true)
		}
		fi, err := os.Stat(*file)
		if err != nil {
			log.Fatal("Error stating file for encryption: ", err)
		}

		excludeNames := make(map[string]bool)
		for _, n := range strings.Split(*excludeNamesFlag, ";") {
			excludeNames[n] = true
		}

		fn := func(file string, fi os.FileInfo, err error) error {
			if err != nil {
				log.Fatalf("Error walking files: %v: %v", file, err)
			}
			if excludeNames[fi.Name()] {
				if fi.IsDir() {
					return filepath.SkipDir
				} else {
					return nil
				}
			}
			if !fi.IsDir() {
				encryptFileAndStoreMetadata(aesKey, hmacKey, ivKey, chunkStore, *chunkBytes, db, file, fi)
			}
			return nil
		}
		if fi.IsDir() {
			if !excludeNames[filepath.Base(*file)] {
				filepath.Walk(*file, fn)
			}
		} else {
			fn(*file, fi, nil)
		}
	case "decrypt":
		entries, err := db.Get(*file)
		if err != nil {
			log.Fatalf("Error getting entries: %v", err)
		}
		tempDir, err := ioutil.TempDir("", "cloudbackuptmp")
		if err != nil {
			log.Fatal("Unable to make temporary directory: ", err)
		}
		paths := make([]string, 0, len(entries))
		for path, _ := range entries {
			paths = append(paths, path)
		}
		// Ensure that directories are made before the files in them.
		sort.Strings(paths)
		for _, path := range paths {
			e := entries[path]
			if e.Mode.IsDir() {
				if !fscache.Exists(path) {
					if err := os.Mkdir(path, e.Mode); err != nil {
						log.Fatalf("Unable to mkdir %q: %v", path, err)
					}
					chown(path, path, &e)
				}
			} else {
				decryptFile(aesKey, hmacKey, chunkStore, &e, tempDir, path)
			}
		}
	}
}

func fatal(message string, includeUsage bool) {
	fmt.Fprintln(os.Stderr, message)
	if includeUsage {
		flag.PrintDefaults()
	}
	os.Exit(2)
}

func generateKeys(path string) {
	toWrite := make([]byte, 0, 300)
	keyBuf := make([]byte, keySize)
	for _, t := range []string{"Authentication", "Encryption", "IV"} {
		_, err := rand.Read(keyBuf)
		if err != nil {
			log.Fatalf("Error generating random keys: %v", err)
		}
		toWrite = append(toWrite, pem.EncodeToMemory(&pem.Block{
			Type:  t,
			Bytes: keyBuf,
		})...)
	}
	if err := ioutil.WriteFile(path, toWrite, 0600); err != nil {
		log.Fatalf("Error writing keyfile: %v", err)
	}
}

func parseChunkSpec(chunkSpec string, keys map[string][]byte) (chunkStoreInterface, error) {
	var wantParts int
	if strings.HasPrefix(chunkSpec, "local:") {
		wantParts = 2
	} else if strings.HasPrefix(chunkSpec, "gcs:") {
		wantParts = 3
	} else {
		return nil, fmt.Errorf("chunk spec must be of form [local|gcs]:foo")
	}
	parts := strings.SplitN(chunkSpec, ":", wantParts)
	switch parts[0] {
	case "local":
		dir := parts[1]
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("error making chunk directory: %v", err)
		}
		return &files.ChunkStore{
			dir,
		}, nil
	case "gcs":
		if len(parts) != 3 {
			return nil, fmt.Errorf("gcs chunk spec must be of form gcs:json-keyfile:bucket")
		}
		client, err := storage.NewClient(context.Background(), option.WithServiceAccountFile(parts[1]))
		if err != nil {
			return nil, err
		}
		return &gcs.ChunkStore{
			Bucket: client.Bucket(parts[2]),
			OptimizeForRepeatedSaves: false,
		}, nil
	default:
		return nil, fmt.Errorf("didn't know how to make ChunkSpec for scheme %s", parts[0])
	}
}

func encryptFileAndStoreMetadata(aesKey, hmacKey, ivKey []byte, chunkStore chunkStoreInterface, chunkBytes int, db *meta.DB, file string, fi os.FileInfo) {
	f, err := os.Open(file)
	if err != nil {
		log.Fatal("Error opening file for encryption: ", err)
	}
	defer f.Close()

	chunks := encryptFile(aesKey, hmacKey, ivKey, chunkStore, chunkBytes, f)

	entry, err := makeEntry(fi, chunks)
	if err != nil {
		log.Fatalf("Error making entry for %q: %v", file, err)
	}
	newBuckets, err := db.Put(file, entry)
	if err != nil {
		log.Fatalf("Error putting dir %q in database: %v", file, err)
	}
	for _, newBucket := range newBuckets {
		dirFI, err := os.Stat(newBucket)
		if err != nil {
			log.Fatalf("Error stating dir %q: %v", newBucket, err)
		}
		dirEntry, err := makeEntry(dirFI, nil)
		if err != nil {
			log.Fatalf("Error making entry for dir %q: %v", newBucket, err)
		}
		if _, err := db.Put(newBucket+"/.", dirEntry); err != nil {
			log.Fatalf("Error putting dir %q in database: %v", newBucket, err)
		}
	}
}

func makeEntry(fi os.FileInfo, chunks []meta.Chunk) (*meta.Entry, error) {
	st := fi.Sys().(*syscall.Stat_t)
	owningUser, err := fscache.LookupUID(st.Uid)
	if err != nil {
		return nil, err
	}
	owningGroup, err := fscache.LookupGID(st.Gid)
	if err != nil {
		return nil, err
	}

	var bytes int64
	if !fi.IsDir() {
		bytes = fi.Size()
	}

	return &meta.Entry{
		bytes,
		chunks,
		fi.Mode(),
		owningUser,
		owningGroup,
	}, nil
}

func encryptFile(aesKey, hmacKey, ivKey []byte, chunkStore chunkStoreInterface, chunkBytes int, f *os.File) []meta.Chunk {
	nextChunk := files.ReadChunks(f, chunkBytes)

	var chunks []meta.Chunk

	for {
		plaintext, _, err := nextChunk()
		if err != nil {
			log.Fatal("Error reading file for encryption: ", err)
		}
		if plaintext == nil {
			break
		}

		iv := hmac.New(sha256.New, ivKey).Sum(plaintext)[:aes.BlockSize]

		ciphertext, ciphertextMAC, err := crypto.Encrypt(aesKey, hmacKey, iv, plaintext, chunkBytes)
		if err != nil {
			log.Fatal("Error encrypting file: ", err)
		}
		ciphertextMACString := hex.EncodeToString(ciphertextMAC)

		if err := chunkStore.Save(ciphertextMACString, ciphertext); err != nil {
			log.Fatal("Error saving encrypted file: ", err)
		}

		chunks = append(chunks, meta.Chunk{iv, ciphertextMAC})
	}
	return chunks
}

func decryptFile(aesKey, hmacKey []byte, chunkStore chunkStoreInterface, e *meta.Entry, tempDir, file string) {
	var accumulatedLength int64

	outFile, err := ioutil.TempFile(tempDir, filepath.Base(file))
	defer outFile.Close()
	if err != nil {
		log.Fatal("Error making temporary file for writing: ", err)
	}

	for _, chunk := range e.Chunks {
		ciphertext, err := chunkStore.Read(hex.EncodeToString(chunk.CiphertextMAC))
		if err != nil {
			log.Fatal("Error reading encrypted chunk: ", err)
		}

		plaintextChunk, err := crypto.Decrypt(aesKey, hmacKey, chunk.IV, ciphertext, chunk.CiphertextMAC)
		if err != nil {
			log.Fatalf("Decrypting chunk %s (length: %v) with IV %s got error %v", chunk.CiphertextMAC, len(ciphertext), chunk.IV, err)
		}
		if accumulatedLength+int64(len(plaintextChunk)) > e.Bytes {
			plaintextChunk = plaintextChunk[:int(e.Bytes-accumulatedLength)]
		}
		accumulatedLength += int64(len(plaintextChunk))
		if _, err := outFile.Write(plaintextChunk); err != nil {
			log.Fatal("Error writing decrypted file: ", err)
		}
	}
	if err := os.Chmod(outFile.Name(), e.Mode); err != nil {
		log.Fatalf("Error chmoding file %v to %v: %v", outFile.Name(), strconv.FormatUint(uint64(e.Mode), 8), err)
	}
	chown(file, outFile.Name(), e)
	if err := os.Rename(outFile.Name(), file); err != nil {
		log.Fatalf("Error renaming temporary file %v to output file %v: %v", outFile.Name(), file, err)
	}
}

func chown(nameForErrors, path string, e *meta.Entry) {
	uid, err := fscache.LookupUser(e.User)
	if err != nil {
		log.Printf("Could not find user %q on this system - skipping chown for %q (%v)", e.User, nameForErrors, err)
	} else {
		gid, err := fscache.LookupGroup(e.Group)
		if err != nil {
			log.Printf("Could not find group %q on this system - skipping chown for %q (%v)", e.Group, nameForErrors, err)
		} else {
			if err := os.Chown(path, int(uid), int(gid)); err != nil {
				log.Printf("Error chowning file %v (for %q): %v", path, nameForErrors, err)
			}
		}
	}
}

type chunkStoreInterface interface {
	Read(hmac string) ([]byte, error)
	Save(hmac string, contents []byte) error
}
