// Package rate 提供 per-IP 并发连接上限
package rate

import "sync"

type Limiter struct {
	mu     sync.Mutex
	active map[string]int
	max    int
}

func New(max int) *Limiter {
	return &Limiter{active: make(map[string]int), max: max}
}

// Acquire 记录一个来自 ip 的新连接；超限返回 false
func (l *Limiter) Acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.active[ip]
	if n >= l.max {
		return false
	}
	l.active[ip] = n + 1
	return true
}

func (l *Limiter) Release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n := l.active[ip]; n <= 1 {
		delete(l.active, ip)
	} else {
		l.active[ip] = n - 1
	}
}
