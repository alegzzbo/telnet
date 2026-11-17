package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseWaitCommand(t *testing.T) {
	cases := []struct {
		in      string
		pat     string
		timeout int
	}{
		{"wait:login:", "login:", 7},
		{"wait:login:10", "login", 10},
		{"wait:foo:0", "foo", 0},
		{"wait:Password:", "Password:", 7},
	}
	for _, c := range cases {
		p, to := parseWaitCommand(c.in, "wait:", 7)
		if p != c.pat || to != c.timeout {
			t.Errorf("%q => %q,%d; want %q,%d", c.in, p, to, c.pat, c.timeout)
		}
	}
}

func TestRingBuffer(t *testing.T) {
	r := NewRingBuffer(8)
	r.Write([]byte("abcdef"))
	r.Write([]byte("ghij"))
	if got := r.String(); got != "cdefghij" {
		t.Fatalf("got %q", got)
	}
	r.Write([]byte("0123456789XYZ"))
	if got := r.String(); got != "6789XYZ"[0:0]+"56789XYZ" {
		t.Fatalf("got %q", got)
	}
	if r.TotalWritten() != 6+4+13 {
		t.Fatalf("total %d", r.TotalWritten())
	}
}

func TestNormalizeInput(t *testing.T) {
	got := normalizeInput([]byte{'a', '\r', 0x7f, IAC})
	want := []byte{'a', '\r', '\n', 0x08, IAC, IAC}
	if string(got) != string(want) {
		t.Fatalf("got %v", got)
	}
}

func TestNormalizeAddr(t *testing.T) {
	for in, want := range map[string]string{
		"host": "host:23", "host:2323": "host:2323", "::1": "[::1]:23", "[::1]:99": "[::1]:99",
	} {
		if got := normalizeAddr(in, "23"); got != want {
			t.Errorf("%s => %s want %s", in, got, want)
		}
	}
}

// wait не должен срабатывать на старый вывод.
func TestWaitIgnoresOldOutput(t *testing.T) {
	lastOutput = NewRingBuffer(8192)
	lastOutput.Write([]byte("login: "))
	snap := lastOutput.TotalWritten()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if waitFor(ctx, func(s string) bool { return strings.Contains(s, "login:") }, snap, 1) {
		t.Fatal("matched old output")
	}
	go func() { time.Sleep(150 * time.Millisecond); lastOutput.Write([]byte("Password: ")) }()
	if !waitFor(ctx, func(s string) bool { return strings.Contains(s, "Password:") }, snap, 2) {
		t.Fatal("did not match new output")
	}
}

// Сценарий on_connect с реальным сокетом.
func TestOnConnectScript(t *testing.T) {
	lastOutput = NewRingBuffer(8192)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	got := make(chan string, 4)
	go func() {
		s, _ := ln.Accept()
		s.Write([]byte("login: "))
		buf := make([]byte, 64)
		n, _ := s.Read(buf)
		got <- string(buf[:n])
		s.Write([]byte("Password: "))
		n, _ = s.Read(buf)
		got <- string(buf[:n])
	}()
	addr = ln.Addr().String()
	if err := connect(); err != nil {
		t.Fatal(err)
	}
	defer closeConn()
	startOnConnect([]string{"wait:login:5", "user", "wait:Password:5", "pass"})
	for _, want := range []string{"user\r\n", "pass\r\n"} {
		select {
		case g := <-got:
			if g != want {
				t.Fatalf("got %q want %q", g, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
	}
}
