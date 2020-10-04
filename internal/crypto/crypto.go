package crypto

import (
	"io"
	"os"
)

type Crypto interface {
	DeriveKey(password string) (key []byte, err error)
	Encrypt(plaintextFile, ciphertextFile file, key []byte) (err error)
	Decrypt(ciphertextFile, plaintextFile file, key []byte) (err error)
}

type crypto struct {
	ioReadFull ioReadFullFunc
}

func New() Crypto {
	return &crypto{
		ioReadFull: io.ReadFull,
	}
}

type ioReadFullFunc func(r io.Reader, dst []byte) (n int, err error)

type file interface {
	Read(b []byte) (n int, err error)
	ReadAt(b []byte, off int64) (n int, err error)
	Write(b []byte) (n int, err error)
	Stat() (os.FileInfo, error)
}
