//go:build !windows

package main

import (
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

// watchWindowSize шлёт NAWS при изменении размера терминала (если сервер согласился).
func watchWindowSize() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	for range ch {
		if atomic.LoadInt32(&nawsActive) == 1 {
			if c := getConn(); c != nil {
				sendWindowSize(c)
			}
		}
	}
}
