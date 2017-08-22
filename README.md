# cloudbackup

cloudbackup encrypts files and stores them to cloud storage.

Example usage:
```
cloudbackup encrypt --key-file=/path/to/keys.pem --meta-file=/path/to/metadata/file --chunkspec=gcs:/path/to/gcs/keys.json:bucket-name --file="/path/to/file" --chunk-bytes=2097152
```

This will save the encrypted file in chunks, and save the metadata required for decryption to the metadata file. If `--file` is a directory, it will recursively encrypt and store all files in the directory. Behaviour when encountering symlinks is undefined.

```
cloudbackup decrypt --key-file=/path/to/keys.pem --meta-file=/path/to/metadata/file --chunkspec=gcs:/path/to/gcs/key.json:bucket-name --file="/path/to/file"
```

## Arguments
**--key-file**: A PEM-encoded file containing two keys; one named Encryption which is a 256-bit key used for AES encryption, one named Authentication which is a 256-bit key used for HMAC.

**--meta-file**: A boltdb file containing a bucket named files, where metadata required for decryption is stored (e.g. file-chunk mappings). This file will be created if it does not already exist.

**--chunkspec**: A specification of where to store the encrypted chunks. For Google Cloud Storage, this value should be: gcs:path-to-key:bucket-name - a JSON key file can be obtained as per https://cloud.google.com/storage/docs/authentication#generating-a-private-key

**--file**: The path of the file to encrypt or decrypt. If decrypting, this file will be created (or overwritten) atomically.

### For encryption:
**--chunk-bytes**: The number of bytes to store in each encrypted chunk. Smaller files (or trailing chunks) will be padded such that all chunks are an identical size. This padding will be stripped on decryption.

**--exclude-names**: File or directory names to skip.

## Weaknesses

### Keys
If these are compromised, so is all data.

### Metadata file
If someone manages to obtain or decrypt your metadata file, they get a whole lot of information. The most important things they get are:
 * Filenames of every backed up file.
 * Sizes of every backed up file.
 * Pointers to the encrypted chunks to try to decrypt for any particular file.
 * HMAC with SHA256 of the plaintext of each chunk (used as the IV - you could choose to use another IV scheme, like random bytes, or a hash of the filename, or something - each of these offers different trade-offs). The HMAC uses a key, so this shouldn't give too much information to an attacker, but if HMAC-SHA256 is broken in some way, it could be a problem.

### Algorithms
 * AES (if this is broken, all your data are compromised).
 * HMAC-SHA256 (see Metadata file section).

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