# cloudbackup [![Build Status](https://travis-ci.org/illicitonion/cloudbackup.svg?branch=master)](https://travis-ci.org/illicitonion/cloudbackup)

cloudbackup encrypts files and stores them to cloud storage.

Example usage:
```
cloudbackup encrypt --key-file=/path/to/keys.pem --chunkspec=gcs:/path/to/gcs/keys.json:bucket-name --file="/path/to/file" --chunk-bytes=2097152
```

This will save the encrypted file in chunks, and save the metadata required for decryption to a metadata file which in turn will be encrypted and stored. If `--file` is a directory, it will recursively encrypt and store all files in the directory. Behaviour when encountering symlinks is undefined.

```
cloudbackup decrypt --key-file=/path/to/keys.pem --chunkspec=gcs:/path/to/gcs/key.json:bucket-name --file="/path/to/file"
```

## Arguments
**--key-file**: A PEM-encoded file containing two keys; one named Encryption which is a 256-bit key used for AES encryption, one named Authentication which is a 256-bit key used for HMAC.

**--chunkspec**: A specification of where to store the encrypted chunks. For Google Cloud Storage, this value should be: gcs:path-to-key:bucket-name - a JSON key file can be obtained as per https://cloud.google.com/storage/docs/authentication#generating-a-private-key

**--file**: Relative path of the file or directory to encrypt or decrypt. If decrypting, this file will be created (or overwritten) atomically. -file=. will encrypt the whole current working directory (recursively), or decrypt all known files.

**--meta-file**: (Optional). This should not normally be used - by default, this file will be encrypted and stored alongside chunks. Specifying this manually will prevent automatic upload of the metadata file, and lead to you needing to manually merge things. A boltdb file containing a bucket named files, where metadata required for decryption is stored (e.g. file-chunk mappings). This file will be created if it does not already exist.

### For encryption:
**--chunk-bytes**: The number of bytes to store in each encrypted chunk. Smaller files (or trailing chunks) will be padded such that all chunks are an identical size. This padding will be stripped on decryption. This must be at least as large as a single meta.Entry (which is about 256 bytes).

**--exclude-names**: File or directory names to ignore; semicolon-delimited

## What it does

A file is split into plaintext chunks of equal size. The last chunk is padded with null bytes if it is smaller than a whole chunk.

Each chunk is encrypted with AES-256 using the Encryption key, using CBC across blocks within a chunk. The IV used is random.

Each chunk is stored in cloud storage, named with the HMAC-SHA256 of the ciphertext chunk using the Authentication key (distinct from both the Encryption key).

An entry is added to a metadata file which contains a mapping of:

```
filename -> {
 Size of file in bytes (for removing padding)
 Mode of file (to set permissions on decryption)
 Owning username and group name of file (to chown on decryption)
 List of Ciphertext HMACs for each chunk (to find them), and their IVs (to decrypt them)
}
```

encoded in the Go "gob" format (https://golang.org/pkg/encoding/gob/).

This metadata file is gzip'd and encrypted with the Encryption key just as any other file would be.

A file called "meta" is created which contains the metadata-file value for the metadata file (i.e. its size/mode/... tuple). This value is encrypted with AES-256 with the Encryption key, with constant IV "metametametameta", and the ciphertext is uploaded to cloud storage. This allows the metadata file to be found and fetched.

## Weaknesses

### Keys
If these are compromised, so is all data.

### Metadata file
If someone manages to obtain or decrypt your metadata file, they get a whole lot of information. The most important things they get are:
 * Filenames of every backed up file.
 * Sizes of every backed up file.
 * Pointers to the encrypted chunks to try to decrypt for any particular file.

### Algorithms
 * AES (if this is broken, all your data are compromised) in CBC mode.
 * HMAC-SHA256 (used to authenticate that ciphertexts have not been tampered with).

### Traffic analysis
This software uploads and downloads chunks sequentially. Anyone who can watch your traffic (or server storage timestamps) can gain some information about your stored data (e.g. "This file is probably the metadata file" or "These five chunks seem to be ordered this way probably in one file"). No attempts are made to cover up timings (e.g. disk seeks switching between files). Some randomisation/delay/similar could be added if someone cared much. Harder, is hiding higher level patterns like "700MB seems to be uploaded every week when Dr Who is being broadcast", short of uploading random chunks.

## OpenSSL equivalents for operating on single chunks

Encrypting:
```
openssl aes-256-cbc -in <(echo -n "foo" ; cat /dev/zero | head -c $((2097152 - 3))) -nopad -K 0000000000000000000000000000000000000000000000000000000000000000 -iv 00000000000000000000000000000000
```

Decrypting:
```
openssl aes-256-cbc -d -in /path/to/chunk -K 0000000000000000000000000000000000000000000000000000000000000000 -iv 00000000000000000000000000000000 | head -c ${bytes}
```

## Metadata storage

In the chunk store, a single `meta.Entry` is encrypted and stored as the chunk named `meta` (with constant IV `metametametameta`). This points at the encrypted chunks of a gzip'd boltdb metadata file.
