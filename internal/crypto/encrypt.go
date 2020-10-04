package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func (c *crypto) Encrypt(plaintextFile, ciphertextFile file, key []byte) (err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cannot create AES block cipher: %w", err)
	}
	blockSize := block.BlockSize()

	iv, err := makeIV(c.ioReadFull, blockSize)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)

	// Memory buffer to use for encryption
	const bufferSize = 16 * 6400 // 100 KiB
	buffer := make([]byte, bufferSize)

	for {
		if done, err := encryptStep(plaintextFile, ciphertextFile, stream, buffer); err != nil {
			return err
		} else if done {
			break
		}
	}

	if err := appendIVToFile(ciphertextFile, iv); err != nil {
		return err
	}
	return nil
}

func makeIV(ioReadFull ioReadFullFunc, blockSize int) (iv []byte, err error) {
	iv = make([]byte, blockSize)
	if randomBytesRead, err := ioReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for IV: %w", err)
	} else if randomBytesRead != blockSize {
		return nil, fmt.Errorf("read %d random bytes instead of %d bytes for IV", randomBytesRead, blockSize) //nolint:err113
	}
	return iv, nil
}

func encryptStep(plaintextFile, ciphertextFile file, stream cipher.Stream, buffer []byte) ( //nolint:interfacer
	done bool, err error) {
	bytesRead, err := plaintextFile.Read(buffer)
	switch {
	case err == io.EOF:
		return true, nil
	case err != nil:
		return false, fmt.Errorf("cannot read %d bytes: %w", bytesRead, err)
	case bytesRead > 0:
		stream.XORKeyStream(buffer, buffer[:bytesRead])
		writtenBytes, err := ciphertextFile.Write(buffer[:bytesRead])
		if err != nil {
			return false, fmt.Errorf("cannot write to ciphertext file: %w", err)
		} else if writtenBytes != bytesRead {
			return false, fmt.Errorf("wrote %d bytes instead of %d bytes to ciphertext file", writtenBytes, bytesRead) //nolint:err113
		}
		return false, nil
	default:
		return false, nil
	}
}

func appendIVToFile(f file, iv []byte) (err error) {
	writtenBytes, err := f.Write(iv)
	if err != nil {
		return fmt.Errorf("cannot write to ciphertext file: %w", err)
	} else if writtenBytes != len(iv) {
		return fmt.Errorf("wrote %d bytes instead of %d bytes for IV in ciphertext file", writtenBytes, len(iv)) //nolint:err113
	}
	return nil
}
