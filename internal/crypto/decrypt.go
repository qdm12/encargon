package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

func (c *crypto) Decrypt(ciphertextFile, plaintextFile file, key []byte) (err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	blockSize := block.BlockSize()

	ciphertextFileSize, err := getFileSize(ciphertextFile)
	if err != nil {
		return fmt.Errorf("cannot get ciphertext file size: %w", err)
	}
	ciphertextLength := ciphertextFileSize - int64(blockSize)

	iv, err := extractIVFromFile(ciphertextFile, ciphertextLength, blockSize)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)

	const bufferSize = 16 * 6400 // 100 KiB
	buffer := make([]byte, bufferSize)

	done := false
	for {
		ciphertextLength, done, err = decryptStep(ciphertextFile, plaintextFile, ciphertextLength, stream, buffer)
		if err != nil {
			return err
		} else if done {
			break
		}
	}
	return nil
}

func getFileSize(f file) (size int64, err error) {
	stats, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return stats.Size(), nil
}

func extractIVFromFile(ciphertextFile file, ciphertextLength int64, blockSize int) (iv []byte, err error) {
	iv = make([]byte, blockSize)
	bytesRead, err := ciphertextFile.ReadAt(iv, ciphertextLength)
	if err != nil {
		return nil, fmt.Errorf("cannot read IV from ciphertext file: %w", err)
	} else if bytesRead != blockSize {
		return nil, fmt.Errorf("read %d bytes instead of %d bytes for IV", bytesRead, blockSize) //nolint:err113
	}
	return iv, nil
}

func decryptStep(ciphertextFile, plaintextFile file, ciphertextLength int64, stream cipher.Stream, //nolint:interfacer
	buffer []byte) (updatedCiphertextLength int64, done bool, err error) {
	bytesRead, err := ciphertextFile.Read(buffer)
	switch {
	case err == io.EOF:
		return 0, true, nil
	case err != nil:
		return ciphertextLength, false, fmt.Errorf("cannot read %d bytes: %w", bytesRead, err)
	case bytesRead > 0:
		if bytesRead > int(ciphertextLength) {
			// we are passed the ciphertext and are reading the IV at the end
			bytesRead = int(ciphertextLength)
		}
		ciphertextLength -= int64(bytesRead)
		stream.XORKeyStream(buffer, buffer[:bytesRead])
		writtenBytes, err := plaintextFile.Write(buffer[:bytesRead])
		if err != nil {
			return ciphertextLength, false, fmt.Errorf("cannot write to plaintext file: %w", err)
		} else if writtenBytes != bytesRead {
			err := fmt.Errorf("wrote %d bytes instead of %d bytes to plaintext file", writtenBytes, bytesRead) //nolint:err113
			return ciphertextLength, false, err
		}
		return ciphertextLength, false, nil
	default:
		return ciphertextLength, false, nil
	}
}
