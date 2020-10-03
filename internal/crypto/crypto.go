package crypto

type Crypto interface {
	DeriveKey(password string) (key []byte, err error)
	Encrypt(plaintext, key []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext, key []byte) (plaintext []byte, err error)
}

type crypto struct{}

func New() Crypto {
	return &crypto{}
}
