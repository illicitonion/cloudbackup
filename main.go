package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
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

var metaIV = []byte("metametametameta")

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

	var metaFileFlag, chunkSpec, file, excludeNamesFlag *string
	var reupload *bool
	var chunkBytes *int
	if command != "keygen" {
		chunkSpec = flag.String("chunkspec", "", "Spec of where to save chunks. Valid values: local:/path/to/local/directory, gcs:path-to-json-keyfile:bucket-name")
		file = flag.String("file", "", "Relative path of the file or directory to encrypt or decrypt. If decrypting, this file will be created (or overwritten) atomically. --file=. will encrypt the whole current working directory (recursively), or decrypt all known files.")
		metaFileFlag = flag.String("meta-file", "", "(Optional). This should not normally be used - by default, this file will be encrypted and stored alongside chunks. Specifying this manually will prevent automatic upload of the metadata file, and lead to you needing to manually merge things. A boltdb file containing a bucket named files, where metadata required for decryption is stored (e.g. file-chunk mappings). This file will be created if it does not already exist.")

		if command == "encrypt" {
			chunkBytes = flag.Int("chunk-bytes", -1, "The number of bytes to store in each encrypted chunk. Smaller files (or trailing chunks) will be padded such that all chunks are an identical size. This padding will be stripped on decryption. This must be at least as large as a single meta.Entry (which is about 256 bytes).")
			excludeNamesFlag = flag.String("exclude-names", "", "File or directory names to ignore; semicolon-delimited.")
			reupload = flag.Bool("reupload", false, "Whether to re-upload chunks which have not changed in already uploaded files.")
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
	if len(aesKey) != keySize || len(hmacKey) != keySize {
		fatal("Bad keys: Want each to be 256 bits", false)
	}

	chunkStore, err := parseChunkSpec(*chunkSpec, keys)
	if err != nil {
		log.Fatal("Error parsing chunk spec: ", err)
	}

	tempDir, err := ioutil.TempDir("", "cloudbackuptmp")
	if err != nil {
		log.Fatal("Unable to make temporary directory: ", err)
	}

	var metaFile string

	if *metaFileFlag == "" {
		metaFile = fetchMetadataFile(aesKey, hmacKey, chunkStore, tempDir)
	} else {
		metaFile = *metaFileFlag
	}

	db, err := meta.NewDB(metaFile)
	if err != nil {
		log.Fatalf("Error opening database at %v: %v", metaFile, err)
	}
	defer db.Close()

	switch command {
	case "encrypt":
		if *chunkBytes <= 0 || *chunkBytes%aes.BlockSize != 0 {
			fatal(fmt.Sprintf("Need -chunk-bytes greater than zero, and a multiple of %v got %v", aes.BlockSize, *chunkBytes), true)
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
				encryptFileAndStoreMetadata(aesKey, hmacKey, chunkStore, *chunkBytes, db, file, fi, *reupload)
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

		if *metaFileFlag == "" {
			db.Close()
			uploadMetadataFile(aesKey, hmacKey, chunkStore, metaFile, *chunkBytes)
		}
	case "decrypt":
		entries, err := db.Get(*file)
		if err != nil {
			log.Fatalf("Error getting entries: %v", err)
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
	for _, t := range []string{"Authentication", "Encryption"} {
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
		return &gcs.ChunkStore{Bucket: client.Bucket(parts[2])}, nil
	default:
		return nil, fmt.Errorf("didn't know how to make ChunkSpec for scheme %s", parts[0])
	}
}

func fetchMetadataFile(aesKey, hmacKey []byte, chunkStore chunkStoreInterface, tempDir string) string {
	path := filepath.Join(tempDir, "metadb")

	metaPointerCiphertext, err := chunkStore.Read("meta")
	if err != nil && (err == os.ErrNotExist || strings.Contains(err.Error(), "no such file")) {
		return path
	}
	if err != nil {
		log.Fatalf("Error reading meta file from chunk storage: %v", err)
	}
	metaPointerPlaintext, err := crypto.Decrypt(aesKey, nil, metaIV, metaPointerCiphertext, nil)
	if err != nil {
		log.Fatalf("Error decrypting meta file: %v", err)
	}
	entry, err := meta.DecodeEntry(metaPointerPlaintext)
	if err != nil {
		log.Fatalf("Error decoding meta file: %v", err)
	}
	buf := bytes.NewBuffer(nil)
	decryptChunks(aesKey, hmacKey, buf, chunkStore, entry)
	unzipped, err := gzip.NewReader(buf)
	if err != nil {
		log.Fatalf("Error making gzip reader: %v", err)
	}
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("Error creating metadb file: %v", err)
	}
	if err := f.Chmod(0600); err != nil {
		log.Fatalf("Error chmoding metadb file: %v", err)
	}
	if _, err := io.Copy(f, unzipped); err != nil {
		log.Fatalf("Error writing metadb file: %v", err)
	}
	if err := unzipped.Close(); err != nil {
		log.Fatalf("Error closing gzip decoder: %v", err)
	}
	if err := f.Close(); err != nil {
		log.Fatalf("Error closing metadb file: %v", err)
	}
	return path
}

func uploadMetadataFile(aesKey, hmacKey []byte, chunkStore chunkStoreInterface, metaFile string, chunkBytes int) {
	dbFile, err := ioutil.ReadFile(metaFile)
	if err != nil {
		log.Fatalf("Error reading boltdb file: %v", err)
	}
	zipped := bytes.NewBuffer(nil)
	zipper := gzip.NewWriter(zipped)
	if _, err := zipper.Write(dbFile); err != nil {
		log.Fatalf("Error gzipping boltdb file: %v", err)
	}
	if err := zipper.Close(); err != nil {
		log.Fatalf("Error gzipping boltdb file: %v", err)
	}
	zippedBytes := int64(zipped.Len())
	chunks, err := encryptFile(aesKey, hmacKey, makeIV, nil, chunkStore, chunkBytes, "boltdbmeta", zipped, zippedBytes, true)
	if err != nil {
		log.Fatal(err)
	}
	entry := meta.Entry{
		zippedBytes,
		chunks,
		0600,
		"",
		"",
	}
	encoded, err := meta.EncodeEntry(&entry)
	if err != nil {
		log.Fatalf("Error encoding entry: %v", err)
	}
	ciphertext, _, err := crypto.Encrypt(aesKey, hmacKey, metaIV, encoded, chunkBytes)
	if err := chunkStore.Save("meta", ciphertext); err != nil {
		log.Fatalf("Error uploading meta file: %v", err)
	}
}

func encryptFileAndStoreMetadata(aesKey, hmacKey []byte, chunkStore chunkStoreInterface, chunkBytes int, db *meta.DB, file string, fi os.FileInfo, uploadIfUnchanged bool) {
	f, err := os.Open(file)
	if err != nil {
		log.Fatal("Error opening file for encryption: ", err)
	}
	defer f.Close()

	chunks, err := encryptFile(aesKey, hmacKey, makeIV, db, chunkStore, chunkBytes, fi.Name(), f, fi.Size(), uploadIfUnchanged)
	if err != nil {
		log.Fatal(err)
	}

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

type ivFunc func() ([]byte, error)

func makeIV() (iv []byte, err error) {
	iv = make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return nil, err
	}
	return iv, nil
}

// db may be nil if uploadIfUnchanged is true.
func encryptFile(aesKey, hmacKey []byte, makeIV ivFunc, db *meta.DB, chunkStore chunkStoreInterface, chunkBytes int, name string, f io.Reader, fileSize int64, uploadIfUnchanged bool) ([]meta.Chunk, error) {
	nextChunk := files.ReadChunks(name, f, chunkBytes, fileSize)

	var chunks []meta.Chunk

	var oldChunks []meta.Chunk
	if !uploadIfUnchanged {
		oldChunks = getKnownChunks(name, db)
	}

	for i := 0; true; i++ {
		plaintext, _, err := nextChunk()
		if err != nil {
			return nil, fmt.Errorf("reading file for encryption: %v", err)
		}
		if plaintext == nil {
			break
		}

		if !uploadIfUnchanged && i < len(oldChunks) {
			iv := oldChunks[i].IV
			_, ciphertextMAC, err := crypto.Encrypt(aesKey, hmacKey, iv, plaintext, chunkBytes)
			if err == nil && hmac.Equal(ciphertextMAC, oldChunks[i].CiphertextMAC) {
				chunks = append(chunks, oldChunks[i])
				continue
			}
		}

		iv, err := makeIV()
		if err != nil {
			return nil, fmt.Errorf("making IV: %v", err)
		}

		ciphertext, ciphertextMAC, err := crypto.Encrypt(aesKey, hmacKey, iv, plaintext, chunkBytes)
		if err != nil {
			return nil, fmt.Errorf("encrypting file: %v", err)
		}
		ciphertextMACString := hex.EncodeToString(ciphertextMAC)

		if err := chunkStore.Save(ciphertextMACString, ciphertext); err != nil {
			return nil, fmt.Errorf("saving encrypted file: %v", err)
		}

		chunks = append(chunks, meta.Chunk{iv, ciphertextMAC})
	}
	return chunks, nil
}

func getKnownChunks(name string, db *meta.DB) []meta.Chunk {
	entries, err := db.Get(name)
	if err != nil {
		return nil
	}
	entry, ok := entries[name]
	if !ok {
		return nil
	}
	return entry.Chunks
}

func decryptFile(aesKey, hmacKey []byte, chunkStore chunkStoreInterface, e *meta.Entry, tempDir, file string) {
	outFile, err := ioutil.TempFile(tempDir, filepath.Base(file))
	defer outFile.Close()
	if err != nil {
		log.Fatal("Error making temporary file for writing: ", err)
	}

	if err := decryptChunks(aesKey, hmacKey, outFile, chunkStore, e); err != nil {
		log.Fatal(err)
	}

	if err := os.Chmod(outFile.Name(), e.Mode); err != nil {
		log.Fatalf("Error chmoding file %v to %v: %v", outFile.Name(), strconv.FormatUint(uint64(e.Mode), 8), err)
	}
	chown(file, outFile.Name(), e)
	if err := os.Rename(outFile.Name(), file); err != nil {
		log.Fatalf("Error renaming temporary file %v to output file %v: %v", outFile.Name(), file, err)
	}
}

func decryptChunks(aesKey, hmacKey []byte, dst io.Writer, chunkStore chunkStoreInterface, e *meta.Entry) error {
	var accumulatedLength int64

	for _, chunk := range e.Chunks {
		ciphertext, err := chunkStore.Read(hex.EncodeToString(chunk.CiphertextMAC))
		if err != nil {
			return fmt.Errorf("error reading encrypted chunk: %v", err)
		}

		plaintextChunk, err := crypto.Decrypt(aesKey, hmacKey, chunk.IV, ciphertext, chunk.CiphertextMAC)
		if err != nil {
			return fmt.Errorf("decrypting chunk %s (length: %v) with IV %s got error %v", chunk.CiphertextMAC, len(ciphertext), chunk.IV, err)
		}
		if accumulatedLength+int64(len(plaintextChunk)) > e.Bytes {
			plaintextChunk = plaintextChunk[:int(e.Bytes-accumulatedLength)]
		}
		accumulatedLength += int64(len(plaintextChunk))
		if _, err := dst.Write(plaintextChunk); err != nil {
			return fmt.Errorf("error writing decrypted file: %v", err)
		}
	}
	return nil
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
