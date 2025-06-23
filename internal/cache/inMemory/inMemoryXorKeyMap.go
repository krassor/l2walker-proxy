package inMemory

import (
	"context"
	"fmt"
	"sync"
		socks5proxy "app/main.go/internal/socks5Proxy"
)

type XorKeyInMemoryCache struct {
	InMemoryMap map[string] socks5proxy.XorKeys
	mutex       sync.RWMutex
}

func NewXorKeyInMemoryCache() *XorKeyInMemoryCache {
	m := make(map[string] socks5proxy.XorKeys)
	return &XorKeyInMemoryCache{
		InMemoryMap: m,
	}
}

func (r *XorKeyInMemoryCache) Save(ctx context.Context, ipPort string, xorKeys socks5proxy.XorKeys) error {
	if r.InMemoryMap == nil {
		return fmt.Errorf("SaveUserMessage error: Map is not initializate")
	}

	if ipPort == "" {
		return fmt.Errorf("Save error: Empty key \"ipPort\"")
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.InMemoryMap[ipPort] = xorKeys

	return nil
}

func (r *XorKeyInMemoryCache) IsIpPortExist(ctx context.Context, ipPort string) (bool, error) {
	if r.InMemoryMap == nil {
		return false, fmt.Errorf("IsUserExist error: Map is not initializate")
	}

	if ipPort == "" {
		return false, fmt.Errorf("IsUserExist error: Empty key \"ipPort\"")
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, ok := r.InMemoryMap[ipPort]
	if ok {
		return true, nil
	} else {
		return false, nil
	}

}

func (r *XorKeyInMemoryCache) Get(ctx context.Context, ipPort string) (socks5proxy.XorKeys, error) {
	if r.InMemoryMap == nil {
		return socks5proxy.XorKeys{}, fmt.Errorf("Load error: Map is not initializate")
	}

	if ipPort == "" {
		return socks5proxy.XorKeys{}, fmt.Errorf("Load error: Empty key \"ipPort\"")
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	val, ok := r.InMemoryMap[ipPort]
	if ok {
		return val, nil
	} else {
		return socks5proxy.XorKeys{}, fmt.Errorf("Load error: ipPort not found")
	}
}

func (r *XorKeyInMemoryCache) Delete(ctx context.Context, ipPort string) error {
	if r.InMemoryMap == nil {
		return fmt.Errorf("Delete error: Map is not initializate")
	}

	if ipPort == "" {
		return fmt.Errorf("DeleteFirstPromt error: Empty key \"ipPort\"")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, ok := r.InMemoryMap[ipPort]
	if ok {
		delete(r.InMemoryMap, ipPort)
		return nil
	}

	return nil

}
