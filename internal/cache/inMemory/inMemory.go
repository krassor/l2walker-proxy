package inMemory

import (
	"context"
	"fmt"
	"sync"
)

type InMemoryCache struct {
	InMemoryMap map[int64][]interface{}
	mutex       sync.RWMutex
}

func NewInMemoryRepository() *InMemoryCache {
	m := make(map[int64][]interface{})
	return &InMemoryCache{
		InMemoryMap: m,
	}
}

func (r *InMemoryCache) Save(ctx context.Context, userID int64, history []interface{}) error {
	if r.InMemoryMap == nil {
		return fmt.Errorf("SaveUserMessage error: Map is not initializate")
	}

	if userID <= 0 {
		return fmt.Errorf("Save error: Empty key \"userID\"")
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.InMemoryMap[userID] = append(r.InMemoryMap[userID], history...)

	return nil
}

func (r *InMemoryCache) IsUserExist(ctx context.Context, userID int64) (bool, error) {
	if r.InMemoryMap == nil {
		return false, fmt.Errorf("IsUserExist error: Map is not initializate")
	}

	if userID <= 0 {
		return false, fmt.Errorf("IsUserExist error: Empty key \"userID\"")
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, ok := r.InMemoryMap[userID]
	if ok {
		return true, nil
	} else {
		return false, nil
	}

}

func (r *InMemoryCache) Get(ctx context.Context, userID int64) ([]interface{}, error) {
	if r.InMemoryMap == nil {
		return nil, fmt.Errorf("Load error: Map is not initializate")
	}

	if userID <= 0 {
		return nil, fmt.Errorf("Load error: Empty key \"userID\"")
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	val, ok := r.InMemoryMap[userID]
	if ok {
		return val, nil
	} else {
		return nil, fmt.Errorf("Load error: userID not found")
	}
}

func (r *InMemoryCache) Delete(ctx context.Context, userID int64) error {
	if r.InMemoryMap == nil {
		return fmt.Errorf("Delete error: Map is not initializate")
	}

	if userID <= 0 {
		return fmt.Errorf("DeleteFirstPromt error: Empty key \"userID\"")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, ok := r.InMemoryMap[userID]
	if ok {
		delete(r.InMemoryMap, userID)
		return nil
	}

	return nil

}
