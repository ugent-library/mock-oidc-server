package mockoidc

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/bluele/gcache"
)

type Store struct {
	backend gcache.Cache
	file    string
}

func NewStore(file string, size int, duration time.Duration) (*Store, error) {
	backend := gcache.New(size).LRU().Expiration(duration).Build()

	// TODO: flushed logins do not store expiration date
	if _, err := os.Stat(file); err == nil {
		reader, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer reader.Close()

		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			l := Login{}
			if err := json.Unmarshal(scanner.Bytes(), &l); err != nil {
				return nil, err
			}
			backend.Set(l.Sub, &l)
		}

		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	return &Store{
		backend: backend,
		file:    file,
	}, nil
}

func (s *Store) Get(key any) (any, error) {
	val, err := s.backend.Get(key)
	if errors.Is(err, gcache.KeyNotFoundError) {
		return nil, ErrNotFound
	}
	return val, nil
}

func (s *Store) Set(key any, val any) error {
	return s.backend.Set(key, val)
}

func (s *Store) Purge() {
	s.backend.Purge()
}

func (s *Store) FlushToFile() error {
	writer, err := os.Create(s.file)
	if err != nil {
		return err
	}
	defer writer.Close()
	bwriter := bufio.NewWriter(writer)
	defer bwriter.Flush()
	for _, v := range s.backend.GetALL(true) {
		data, err := json.Marshal(v)
		data = append(data, '\n')
		if err != nil {
			return err
		}
		if _, err := bwriter.Write(data); err != nil {
			return err
		}
	}
	return nil
}
