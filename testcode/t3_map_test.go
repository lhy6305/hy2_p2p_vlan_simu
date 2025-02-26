package main

import (
	"sync"
	"testing"
)

var iteTimes = 10000
var writePer = 10000
var mod = 1

func BenchmarkSyncMapGo(b *testing.B) {
	var mp sync.Map
	var wg sync.WaitGroup
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < iteTimes; j++ {
				if i%writePer == mod {
					mp.Store(0, 0)
				} else {
					_, _ = mp.Load(0)
				}
			}

		}(i)
	}
	wg.Wait()
}
func BenchmarkMapGo(b *testing.B) {
	var mp = make(map[int]int)
	var wg sync.WaitGroup
	var lock sync.Mutex
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			for j := 0; j < iteTimes; j++ {
				lock.Lock()
				if i%writePer == mod {
					mp[0] = 0
				} else {
					i = mp[0]
				}
				lock.Unlock()
			}
		}(i)
	}
	wg.Wait()
}
