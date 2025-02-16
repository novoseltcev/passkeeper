package pwdhash

type Hasher interface {
	Generate(data string) ([]byte, error)
	Compare(hash []byte, data string) (bool, error)
}
