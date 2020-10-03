package fs

type FileSystem interface{}

type fileSystem struct{}

func New() FileSystem {
	return &fileSystem{}
}

func (fs *fileSystem) ReadFile(path string) (content []byte, err error) {
	return nil, errNotImplemented
}

func (fs *fileSystem) WriteFile(path string, content []byte) (err error) {
	return errNotImplemented
}
