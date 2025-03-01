package pwdhash

type Hasher interface {
	Generate(data string) (string, error)
	Compare(hash, data string) (bool, error)
}
