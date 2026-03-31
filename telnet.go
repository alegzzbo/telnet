package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"sync"
	"sync/atomic"
	"reflect"

	"golang.org/x/term"
	keyring "github.com/zalando/go-keyring"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
)

const (
	IAC    = 255
	WILL   = 251
	WONT   = 252
	DO     = 253
	DONT   = 254
	SB     = 250
	SE     = 240
	ESCAPE = 0x1d // Ctrl+]
	NAWS   = 31   // Опция размера окна

	// ANSI цвета
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
)

var ansiColors = map[string]string{
	"red":     ColorRed,
	"green":   ColorGreen,
	"yellow":  ColorYellow,
	"blue":    "\033[34m",
	"magenta": "\033[35m",
	"cyan":    ColorCyan,
	"white":   "\033[37m",
	"reset":   ColorReset,
}

var commands = map[string]string{
	"connect":    "connect <host>[:port] - connect to host",
	"savehost":   "savehost [alias] - save current host",
	"keepalive":  "keepalive [sec] - set keepalive",
	"onconnect":  "onconnect edit|show|clear",
	"keys":       "keys import|export|delete|status",
	"status":     "show connection status",
	"resume":     "return to session",
	"quit":       "exit client",
}

var subcommands = map[string][]string{
	"onconnect": {"edit", "show", "clear"},
	"keys":      {"import", "export", "delete", "status"},
}

type Editor struct {
	lines  []string
	row    int
	col    int
}

type RingBuffer struct {
	data         []byte
	size         int
	pos          int
	totalWritten int64
	mu           sync.Mutex
}

// ---- Структуры конфига ----
// ColorConfig описывает правило раскраски.
// Groups — map номера capture-группы ("1", "2"...) → название цвета.
// Группы без упоминания выводятся без цвета.
// Если Groups не задан — весь match красится цветом Color.
type ColorConfig struct {
	Pattern string            `json:"pattern"`
	Color   string            `json:"color"`
	Groups  map[string]string `json:"groups"`
}

type HostConfig struct {
	Alias         string   `json:"alias"`
	Host          string   `json:"host"`
	Port          string   `json:"port"`
	KeepAlive     int      `json:"keepalive"`
	KeepAliveType string   `json:"keepalive_type"` // "space_bs", "0x13", "0x00"
	WaitTimeout   int      `json:"wait_timeout"`
	OnConnect     []string `json:"on_connect"`
}

// DefaultsConfig задаёт значения keepalive по умолчанию для всех хостов.
// Приоритет: хост-конфиг > флаг CLI > defaults из JSON > встроенные значения.
type DefaultsConfig struct {
	KeepAlive     int    `json:"keepalive"`
	KeepAliveType string `json:"keepalive_type"`
	WaitTimeout   int    `json:"wait_timeout"`
}

type ConfigFile struct {
	Defaults DefaultsConfig `json:"defaults"`
	Colors   []ColorConfig  `json:"colors"`
	Hosts    []HostConfig   `json:"hosts"`
}

type CompiledRule struct {
	Re          *regexp.Regexp
	GroupColors []string // индекс = номер группы (0 = весь match); значение = ANSI-код или ""
}

var (
	oldState *term.State
	conn     net.Conn
	addr     string

	idleTimer           *time.Timer
	timerCh             <-chan time.Time
	keepaliveDuration   time.Duration
	keepaliveType       string
	globalKeepalive     int
	globalKeepaliveType string // <--- Добавили глобальную переменную для типа

	configAliases  map[string]HostConfig
	configByHost   map[string]HostConfig // индекс по "host" и "host:port"
	configDefaults DefaultsConfig
	colorRules    []CompiledRule
	colorRulesMutex sync.RWMutex

	serverDisconnect = make(chan struct{}, 1)
	inputLocked  int32 // atomic: 1 = locked
	inEscapeMode int32 // atomic: 1 = escape mode active, readerLoop не пишет в stdout
	secretsAvailable = true
	lastOutput = NewRingBuffer(8192)
	globalWaitTimeout int
	currentWaitTimeout int
	cachedGCM    cipher.AEAD
	cachedGCMErr error
	gcmOnce      sync.Once
	keyOnce sync.Once
	cachedKey []byte
	configCache ConfigFile
	configPath string
	configLoaded bool
	
	escapeHistory []string 
)

func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		data: make([]byte, size),
		size: size,
	}
}

func (r *RingBuffer) Write(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, b := range p {
		r.data[r.pos] = b
		r.pos = (r.pos + 1) % r.size
		r.totalWritten++
	}
}

func (r *RingBuffer) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.totalWritten < int64(r.size) {
		return string(r.data[:r.pos])
	}

	return string(r.data[r.pos:]) + string(r.data[:r.pos])
}

// TotalWritten возвращает суммарное число записанных байт (монотонно растёт).
func (r *RingBuffer) TotalWritten() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.totalWritten
}

// Since возвращает данные записанные после snapshot (значение TotalWritten на момент входа).
func (r *RingBuffer) Since(snapshot int64) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	newBytes := r.totalWritten - snapshot
	if newBytes <= 0 {
		return ""
	}
	if newBytes > int64(r.size) {
		newBytes = int64(r.size)
	}

	end := r.pos
	start := (end - int(newBytes) + r.size) % r.size
	if start < end {
		return string(r.data[start:end])
	}
	return string(r.data[start:]) + string(r.data[:end])
}

func autocomplete(input string) (string, []string) {
	var matches []string

	for cmd := range commands {
		if strings.HasPrefix(cmd, input) {
			matches = append(matches, cmd)
		}
	}

	if len(matches) == 1 {
		return matches[0], nil
	}

	return "", matches
}

func getInlineHelp(line string) string {
	parts := strings.Fields(line)

	if len(parts) == 0 {
		return ""
	}

	cmd := strings.ToLower(parts[0])

	// точное совпадение
	if help, ok := commands[cmd]; ok {
		return help
	}

	// частичное совпадение
	for k, v := range commands {
		if strings.HasPrefix(k, cmd) {
			return v
		}
	}

	return ""
}

func readLineInteractive(stdinChan <-chan []byte, history *[]string) string {
	var line []byte
	cursor := 0
	hIndex := len(*history)

	redraw := func() {
		fmt.Print("\r\033[K")

		prompt := fmt.Sprintf("%stelnet>%s %s", ColorYellow, ColorReset, string(line))

		help := getInlineHelp(string(line))

		if help != "" {
			fmt.Printf("%s  %s%s%s", prompt, ColorCyan, help, ColorReset)
		} else {
			fmt.Print(prompt)
		}

		back := len(line) - cursor
		if back > 0 {
			fmt.Printf("\033[%dD", back)
		}
	}

	redraw() // показываем промпт сразу при входе

	for {
		chunk := <-stdinChan

		for i := 0; i < len(chunk); i++ {
			b := chunk[i]

			// ENTER
			if b == '\r' || b == '\n' {
				fmt.Print("\r\n")
				return string(line)
			}
			
			// TAB
			if b == '\t' {
				input := string(line)
				parts := strings.Fields(input)

				// --- 1. автокомплит команды ---
				if len(parts) <= 1 {
					prefix := input

					full, matches := autocomplete(prefix)

					if full != "" {
						line = []byte(full + " ")
						cursor = len(line)
						redraw()
						continue
					}

					if len(matches) > 1 {
						fmt.Print("\r\n")
						for _, m := range matches {
							fmt.Println(m)
						}
						redraw()
					}

					continue
				}

				// --- 2. автокомплит подкоманд ---
				if len(parts) == 2 {
					cmd := parts[0]
					argPrefix := parts[1]

					if subs, ok := subcommands[cmd]; ok {

						var matches []string
						for _, s := range subs {
							if strings.HasPrefix(s, argPrefix) {
								matches = append(matches, s)
							}
						}

						if len(matches) == 1 {
							line = []byte(cmd + " " + matches[0] + " ")
							cursor = len(line)
							redraw()
							continue
						}

						if len(matches) > 1 {
							fmt.Print("\r\n")
							for _, m := range matches {
								fmt.Println(m)
							}
							redraw()
						}
					}
				}

				continue
			}

			// BACKSPACE
			if b == 0x08 || b == 0x7f {
				if cursor > 0 {
					line = append(line[:cursor-1], line[cursor:]...)
					cursor--
					redraw()
				}
				continue
			}

			// ESC sequences
			if b == 27 && i+2 < len(chunk) && chunk[i+1] == 91 {
				code := chunk[i+2]
				i += 2

				switch code {

				case 65: // ↑ history up
					if len(*history) > 0 && hIndex > 0 {
						hIndex--
						line = []byte((*history)[hIndex])
						cursor = len(line)
						redraw()
					}

				case 66: // ↓ history down
					if hIndex < len(*history)-1 {
						hIndex++
						line = []byte((*history)[hIndex])
					} else {
						hIndex = len(*history)
						line = nil
					}
					cursor = len(line)
					redraw()

				case 67: // →
					if cursor < len(line) {
						cursor++
						redraw()
					}

				case 68: // ←
					if cursor > 0 {
						cursor--
						redraw()
					}
				}

				continue
			}

			// обычный символ
			if b >= 32 && b <= 126 {
				line = append(line[:cursor], append([]byte{b}, line[cursor:]...)...)
				cursor++
				redraw()
			}
		}
	}
}

func enableRaw() {
	var err error
	oldState, err = term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Raw mode error:", err)
	}
}

func disableRaw() {
	if oldState != nil {
		term.Restore(int(os.Stdin.Fd()), oldState)
	}
}

// Keyring funcs
func keyStatus() {
	_, err := keyring.Get("telnet-client", "master_key")

	if err == keyring.ErrNotFound {
		fmt.Println("No master key")
		return
	}

	if err != nil {
		fmt.Println("Keyring error:", err)
		return
	}

	fmt.Println("Master key present")
}

func deleteMasterKey() {
	fmt.Print("Delete master key? (yes/no): ")
	var input string
	fmt.Scanln(&input)

	if input != "yes" {
		fmt.Println("Cancelled")
		return
	}
	
	err := keyring.Delete("telnet-client", "master_key")
	if err != nil {
		fmt.Println("Failed to delete key:", err)
		return
	}
	
	cachedKey = nil
	cachedGCM = nil
	cachedGCMErr = nil
	keyOnce = sync.Once{}
	gcmOnce = sync.Once{}

	fmt.Println("Master key deleted")
}

func validateMasterKeyFromConfig() {
	loadFullConfig()
	for _, h := range configCache.Hosts {
		if len(h.OnConnect) == 0 {
			continue
		}

		for _, cmd := range h.OnConnect {
			if strings.HasPrefix(cmd, "enc:") {
				_, err := decryptString(strings.TrimPrefix(cmd, "enc:"))
				if err != nil {
					fmt.Printf("%s[warn] master key invalid (cannot decrypt secrets)%s\r\n", ColorYellow, ColorReset)
					return
				}
				return
			}
		}
	}
}

func handleKeysCommand(parts []string, stdinChan <-chan []byte) {
	if len(parts) < 2 {
		fmt.Println("Usage: keys export | import | delete | status")
		return
	}

	switch parts[1] {

	case "export":
		exportMasterKey()

	case "import":
		importMasterKey(stdinChan)
		
	case "delete":
		deleteMasterKey()
		
	case "status":
		keyStatus()

	default:
		fmt.Println("Unknown keys command")
	}
}

func exportMasterKey() {
	key, err := keyring.Get("telnet-client", "master_key")
	if err != nil {
		fmt.Println("No master key found")
		return
	}

	enc := base64.StdEncoding.EncodeToString([]byte(key))

	fmt.Println("=== MASTER KEY (keep secret!) ===")
	fmt.Println(enc)
}

func importMasterKey(stdinChan <-chan []byte) {
	fmt.Print("Paste master key (base64): ")

	var input string

	if stdinChan != nil {
		input = readLineRaw(stdinChan)
	} else {
		fmt.Scanln(&input)
	}

	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(input))
	if err != nil {
		fmt.Println("Invalid key")
		return
	}

	err = keyring.Set("telnet-client", "master_key", string(data))
	if err != nil {
		fmt.Println("Failed to store key:", err)
		return
	}

	cachedKey = nil
	cachedGCM = nil
	cachedGCMErr = nil
	keyOnce = sync.Once{}
	gcmOnce = sync.Once{}
	
	fmt.Println("Master key imported")
}

func getGCM() (cipher.AEAD, error) {
	gcmOnce.Do(func() {
		key := getMasterKey()
		if key == nil {
			cachedGCMErr = fmt.Errorf("no master key")
			return
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			cachedGCMErr = err
			return
		}

		cachedGCM, cachedGCMErr = cipher.NewGCM(block)
	})

	return cachedGCM, cachedGCMErr
}

func encryptString(s string) string {
	gcm, err := getGCM()
	if err != nil {
		return ""
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return ""
	}

	data := gcm.Seal(nonce, nonce, []byte(s), nil)

	return base64.StdEncoding.EncodeToString(data)
}

func decryptString(enc string) (string, error) {
	gcm, err := getGCM()
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("invalid base64")
	}

	n := gcm.NonceSize()

	if len(data) < n {
		return "", fmt.Errorf("data too short")
	}

	out, err := gcm.Open(nil, data[:n], data[n:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt failed (wrong key?)")
	}

	return string(out), nil
}

func getMasterKey() []byte {
	keyOnce.Do(func() {
		key, err := keyring.Get("telnet-client", "master_key")

		if err == nil {
			cachedKey = []byte(key)
			return
		}

		if err != keyring.ErrNotFound {
			fmt.Println("[warn] keyring unavailable:", err)
			secretsAvailable = false
			return
		}

		buf := make([]byte, 32)
		_, err = rand.Read(buf)
		if err != nil {
			secretsAvailable = false
			return
		}

		if err := keyring.Set("telnet-client", "master_key", string(buf)); err != nil {
			secretsAvailable = false
		}
		cachedKey = buf
	})

	return cachedKey
}
func processEditorLines(lines []string) []string {
	var result []string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "!secret ") {
			if !secretsAvailable {
				continue
			}

			plain := strings.TrimPrefix(line, "!secret ")
			enc := encryptString(plain)

			if enc == "" {
				continue
			}

			result = append(result, "enc:"+enc)
			continue
		}

		result = append(result, line)
	}

	return result
}

func expandForEdit(cmds []string) []string {
	var result []string

	for _, cmd := range cmds {
		if strings.HasPrefix(cmd, "enc:") {

			if !secretsAvailable {
				continue
			}

			plain, err := decryptString(strings.TrimPrefix(cmd, "enc:"))
			if err != nil {
				continue
			}

			if plain == "" {
				continue
			}

			result = append(result, "!secret "+plain)
			continue
		}

		result = append(result, cmd)
	}

	return result
}

//Expect funcs
func parseWaitCommand(cmd string, prefix string) (string, int) {
	s := cmd[len(prefix):]

	last := strings.LastIndex(s, ":")

	if last == -1 {
		return s, currentWaitTimeout
	}

	timeout, err := strconv.Atoi(s[last+1:])
	if err != nil {
		return s, currentWaitTimeout
	}
    if timeout == 0 {
        return s, 0 // бесконечное ожидание
    }

	return s[:last], timeout
}

func waitForPattern(pattern string, timeout int) bool {
	start := time.Now()

	for {
		found := strings.Contains(lastOutput.String(), pattern)

		if found {
			return true
		}

		if timeout > 0 && time.Since(start) > time.Duration(timeout)*time.Second {
			return false
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func waitForRegex(pattern string, timeout int) bool {
	re, err := regexp.Compile(pattern)

	if err != nil {

		fmt.Printf("\r\n%sInvalid regex: %s%s\r\n", ColorRed, pattern, ColorReset)
		return false
	}

	start := time.Now()

	for {
		found := re.MatchString(lastOutput.String())

		if found {
			return true
		}

		if timeout > 0 && time.Since(start) > time.Duration(timeout)*time.Second {
			return false
		}

		time.Sleep(100 * time.Millisecond)
	}
}


//config funcs
func reloadConfig() {
	configLoaded = false
	loadFullConfig()

	configAliases, configByHost = buildIndexesFromCache()
	buildColorRulesFromCache()

	fmt.Printf("%sConfig reloaded%s\r\n", ColorGreen, ColorReset)
}

func mergeHostConfig(old HostConfig, new HostConfig) HostConfig {
	result := old

	if new.Alias != "" {
		result.Alias = new.Alias
	}

	if new.KeepAlive != 0 {
		result.KeepAlive = new.KeepAlive
	}

	if new.KeepAliveType != "" {
		result.KeepAliveType = new.KeepAliveType
	}

	if new.WaitTimeout != 0 {
		result.WaitTimeout = new.WaitTimeout
	}

	if new.OnConnect != nil {
		result.OnConnect = new.OnConnect
	}

	return result
}

func saveHostToConfig(hostcfg HostConfig) error {
	// 🔥 всегда читаем свежий файл
	data, err := os.ReadFile(configPath)

	var diskConfig ConfigFile

	if err == nil {
		if err := json.Unmarshal(data, &diskConfig); err != nil {
			return err
		}		
	}

	found := false

	for i := range diskConfig.Hosts {
		h := &diskConfig.Hosts[i]

		p := h.Port
		if p == "" {
			p = "23"
		}

		port := hostcfg.Port
		if port == "" {
			port = "23"
		}

		if h.Host == hostcfg.Host && p == port {

			merged := mergeHostConfig(*h, hostcfg)

			if reflect.DeepEqual(*h, merged) {
				return nil
			}

			*h = merged
			found = true
			break
		}
	}

	if !found {
		diskConfig.Hosts = append(diskConfig.Hosts, hostcfg)
	}

	out, err := json.MarshalIndent(diskConfig, "", "  ")
	if err != nil {
		return err
	}

	// 🔥 атомарная запись
	if err := writeConfigAtomic(configPath, out); err != nil {
		return err
	}

	// 🔥 обновляем cache
	configCache = diskConfig
	configAliases, configByHost = buildIndexesFromCache()
	buildColorRulesFromCache()

	return nil
}

func writeConfigAtomic(path string, data []byte) error {
	tmp := path + ".tmp"

	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}

	if err := os.Rename(tmp, path); err != nil {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return os.Rename(tmp, path)
	}

	return nil
}

func expandCommands(cmds []string) []string {
	var result []string

	for _, cmd := range cmds {
		if strings.HasPrefix(cmd, "enc:") {
			if !secretsAvailable {
				continue
			}

			enc := strings.TrimPrefix(cmd, "enc:")
			plain, err := decryptString(enc)
			
			if err != nil || plain == "" {
				continue
			}

			lines := strings.Split(strings.ReplaceAll(plain, "\r\n", "\n"), "\n")
			result = append(result, lines...)
			continue
		}

		result = append(result, cmd)
	}

	return result
}

func loadFullConfig() {
	if configLoaded {
		return
	}

	data, err := os.ReadFile(configPath)
	if err == nil {
		configCache = ConfigFile{}
		if err := json.Unmarshal(data, &configCache); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse config: %v\r\n", err)
		}
	}

	configLoaded = true
}

func buildIndexesFromCache() (map[string]HostConfig, map[string]HostConfig) {
	aliases := make(map[string]HostConfig)
	byHost := make(map[string]HostConfig)

	for _, h := range configCache.Hosts {

		if h.Alias != "" {
			aliases[h.Alias] = h
		}

		if h.Host != "" {
			byHost[h.Host] = h

			port := h.Port
			if port == "" {
				port = "23"
			}

			byHost[h.Host+":"+port] = h
		}
	}

	return aliases, byHost
}

func buildColorRulesFromCache() {
	colorRulesMutex.Lock()
	defer colorRulesMutex.Unlock()

	colorRules = nil

	for _, cr := range configCache.Colors {
		re, err := regexp.Compile(cr.Pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: invalid regex pattern '%s': %v\r\n", cr.Pattern, err)
			continue
		}

		numGroups := re.NumSubexp()
		groupColors := make([]string, numGroups+1)

		if len(cr.Groups) > 0 {
			for idxStr, colorName := range cr.Groups {
				idx, err := strconv.Atoi(idxStr)
				if err != nil || idx < 1 || idx > numGroups {
					continue
				}

				name := strings.ToLower(colorName)
				if code, ok := ansiColors[name]; ok {
					groupColors[idx] = code
				}
			}
		} else {
			name := strings.ToLower(cr.Color)
			if _, ok := ansiColors[name]; !ok {
				name = "cyan"
			}
			groupColors[0] = ansiColors[name]
		}

		colorRules = append(colorRules, CompiledRule{
			Re:          re,
			GroupColors: groupColors,
		})
	}
}
// loadConfigDefaults читает только секцию defaults из telnet.json.
// Вызывается до парсинга флагов, чтобы можно было применить приоритеты.
func loadConfigDefaults() DefaultsConfig {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return DefaultsConfig{}
	}
	var cfg ConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return DefaultsConfig{}
	}
	return cfg.Defaults
}

// findHostConfig ищет конфиг хоста сначала по alias, потом по IP/host (с портом и без).
// target — то, что ввёл пользователь (alias, IP, IP:port, hostname).
func findHostConfig(target string) (HostConfig, bool) {
	if cfg, ok := configAliases[target]; ok {
		return cfg, true
	}
	// Пробуем точное совпадение по host:port или просто host
	if cfg, ok := configByHost[target]; ok {
		return cfg, true
	}
	// Если target содержит порт — пробуем только хостовую часть
	if host, _, err := net.SplitHostPort(target); err == nil {
		if cfg, ok := configByHost[host]; ok {
			return cfg, true
		}
	}
	return HostConfig{}, false
}

func applyColors(text string) string {
	colorRulesMutex.RLock()
	rules := colorRules
	colorRulesMutex.RUnlock()

	if len(rules) == 0 {
		return text
	}

	for _, rule := range rules {
		text = applyRule(rule, text)
	}

	return text
}

func readLineRaw(stdinChan <-chan []byte) string {
	var lineData []byte

	for {
		select {
		case chunk, ok := <-stdinChan:
			if !ok {
				return string(lineData)
			}

			for i := 0; i < len(chunk); i++ {
				b := chunk[i]
				if b == '\r' || b == '\n' {
					if b == '\r' && i+1 < len(chunk) && chunk[i+1] == '\n' {
						i++
					}
					fmt.Print("\r\n")
					return string(lineData)
				}

				if b == 0x08 || b == 0x7f {
					if len(lineData) > 0 {
						lineData = lineData[:len(lineData)-1]
						fmt.Print("\b \b")
					}
					continue
				}

				if b >= 32 && b <= 126 {
					lineData = append(lineData, b)
					fmt.Print(string(b))
				}
			}

		case <-time.After(5 * time.Minute):
			fmt.Println("\r\n[timeout waiting input]")
			return string(lineData)
		}
	}
}

// applyRule применяет одно правило раскраски к строке.
// Если задан только groupColors[0] — красим весь match.
// Если заданы groupColors[N] для N>0 — красим отдельные capture-группы;
// части match вне именованных групп выводятся без цвета.
func applyRule(rule CompiledRule, text string) string {
	matches := rule.Re.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text
	}

	wholeMatchColor := rule.GroupColors[0]
	hasGroupColors := false
	for i := 1; i < len(rule.GroupColors); i++ {
		if rule.GroupColors[i] != "" {
			hasGroupColors = true
			break
		}
	}

	var sb strings.Builder
	sb.Grow(len(text) + len(matches)*32)
	pos := 0

	for _, m := range matches {
		matchStart, matchEnd := m[0], m[1]
		// текст до начала match
		sb.WriteString(text[pos:matchStart])

		if !hasGroupColors {
			// Простой режим: весь match одним цветом
			if wholeMatchColor != "" {
				sb.WriteString(wholeMatchColor)
			}
			sb.WriteString(text[matchStart:matchEnd])
			if wholeMatchColor != "" {
				sb.WriteString(ColorReset)
			}
		} else {
			// Режим групп: обходим содержимое match по кускам
			cursor := matchStart
			for g := 1; g < len(m)/2; g++ {
				gs, ge := m[g*2], m[g*2+1]
				if gs < 0 {
					continue // группа не участвовала в совпадении
				}
				// текст между cursor и началом группы — без цвета
				if cursor < gs {
					sb.WriteString(text[cursor:gs])
				}
				color := ""
				if g < len(rule.GroupColors) {
					color = rule.GroupColors[g]
				}
				if color != "" {
					sb.WriteString(color)
				}
				sb.WriteString(text[gs:ge])
				if color != "" {
					sb.WriteString(ColorReset)
				}
				cursor = ge
			}
			// остаток match после последней группы
			if cursor < matchEnd {
				sb.WriteString(text[cursor:matchEnd])
			}
		}
		pos = matchEnd
	}
	sb.WriteString(text[pos:])
	return sb.String()
}

func runOnConnectCommands(commands []string) {
	if len(commands) == 0 || conn == nil {
		return
	}

	atomic.StoreInt32(&inputLocked, 1)
	defer func() { atomic.StoreInt32(&inputLocked, 0) }()

	time.Sleep(500 * time.Millisecond)

	for _, cmd := range commands {
		if strings.HasPrefix(cmd, "wait:") {
			pattern, timeout := parseWaitCommand(cmd, "wait:")

			ok := waitForPattern(pattern, timeout)

			if !ok {
				fmt.Printf("\r\n%sWait timeout for '%s'%s\r\n", ColorYellow, pattern, ColorReset)
			}

			continue
		}

		if strings.HasPrefix(cmd, "waitre:") {
			pattern, timeout := parseWaitCommand(cmd, "waitre:")

			ok := waitForRegex(pattern, timeout)

			if !ok {
				fmt.Printf("\r\n%sWait timeout for regex '%s'%s\r\n", ColorYellow, pattern, ColorReset)
			}

			continue
		}

		if conn == nil {
			break
		}

		conn.Write([]byte(cmd + "\r\n"))
		time.Sleep(200 * time.Millisecond)
	}
}

func sendWindowSize(conn net.Conn) {
	if conn == nil {
		return
	}
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return
	}

	sizeData := []byte{
		byte(width >> 8), byte(width & 0xff),
		byte(height >> 8), byte(height & 0xff),
	}

	var escaped []byte
	for _, b := range sizeData {
		escaped = append(escaped, b)
		if b == IAC {
			escaped = append(escaped, IAC)
		}
	}

	buf := []byte{IAC, SB, NAWS}
	buf = append(buf, escaped...)
	buf = append(buf, IAC, SE)

	conn.Write(buf)
}

func handleIAC(conn net.Conn, data []byte) {
	if len(data) < 3 || conn == nil {
		return
	}
	cmd := data[1]
	opt := data[2]

	switch cmd {
	case DO:
		if opt == NAWS {
			conn.Write([]byte{IAC, WILL, NAWS})
			sendWindowSize(conn)
		} else {
			conn.Write([]byte{IAC, WONT, opt})
		}
	case WILL:
		conn.Write([]byte{IAC, DO, opt})
	}
}

func normalizeInput(buf []byte) []byte {
	out := make([]byte, 0, len(buf)*2)
	for i := 0; i < len(buf); i++ {
		b := buf[i]
		switch b {
		case '\r':
			out = append(out, '\r', '\n')
			// пропустить следующий \n если он идёт сразу после \r
			if i+1 < len(buf) && buf[i+1] == '\n' {
				i++
			}
		case '\n':
			out = append(out, '\r', '\n')
		case 0x08, 0x7f:
			out = append(out, 0x08)
		default:
			out = append(out, b)
		}
	}
	return out
}

func connect() error {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	conn = c
	go readerLoop(c)
	return nil
}

func applyHostConfig(cfg *HostConfig) {
	if cfg != nil && cfg.KeepAlive > 0 {
		keepaliveDuration = time.Duration(cfg.KeepAlive) * time.Second
	} else {
		keepaliveDuration = time.Duration(globalKeepalive) * time.Second
	}
	
	if cfg != nil && cfg.WaitTimeout > 0 {
        currentWaitTimeout = cfg.WaitTimeout
    } else {
        currentWaitTimeout = globalWaitTimeout
    }

	if cfg != nil && cfg.KeepAliveType != "" {
		keepaliveType = cfg.KeepAliveType
	} else {
		keepaliveType = globalKeepaliveType // Берем из глобального флага
	}

	if keepaliveDuration > 0 {
		if idleTimer == nil {
			idleTimer = time.NewTimer(keepaliveDuration)
			timerCh = idleTimer.C
		} else {
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(keepaliveDuration)
		}
	} else {
		if idleTimer != nil {
			idleTimer.Stop()
			idleTimer = nil
			timerCh = nil
		}
	}
}

func (e *Editor) redraw() {
	fmt.Print("\033[H\033[2J")

	fmt.Println("--- INSERT MODE (Ctrl+D save, Ctrl+C cancel) ---")

	for _, line := range e.lines {
		fmt.Println(line)
	}

	// +2 потому что:
	// 1 строка — header
	// 1 потому что координаты с 1
	fmt.Printf("\033[%d;%dH", e.row+2, e.col+1)
}

func runEditor(stdinChan <-chan []byte, initial []string) ([]string, bool) {
	e := Editor{
		lines: initial,
		row:   0,
		col:   0,
	}
	
	if len(e.lines) == 0 {
		e.lines = []string{""}
	}

	e.redraw()

	for {
		chunk := <-stdinChan

		for i := 0; i < len(chunk); i++ {
			b := chunk[i]

			// Ctrl+D → save
			if b == 4 {
				fmt.Print("\033[H\033[2J")
				return e.lines, true
			}

			// Ctrl+C → cancel
			if b == 3 {
				fmt.Print("\033[H\033[2J")
				fmt.Println("\nCancelled")
				return nil, false
			}

			// ENTER
			if b == '\r' || b == '\n' {
				line := e.lines[e.row]

				left := line[:e.col]
				right := line[e.col:]

				e.lines[e.row] = left

				e.lines = append(
					e.lines[:e.row+1],
					append([]string{right}, e.lines[e.row+1:]...)...,
				)

				e.row++
				e.col = 0

				e.redraw()
				continue
			}

			// BACKSPACE
			if b == 0x08 || b == 0x7f {
				if e.col > 0 {
					line := e.lines[e.row]
					e.lines[e.row] = line[:e.col-1] + line[e.col:]
					e.col--
				} else if e.row > 0 {
					// переход на предыдущую строку
					prev := e.lines[e.row-1]
					current := e.lines[e.row]

					e.lines[e.row-1] = prev + current

					// удалить текущую строку
					e.lines = append(e.lines[:e.row], e.lines[e.row+1:]...)
	
					e.row--
					e.col = len(prev)
				}

				e.redraw()
				continue
			}

			// ESC sequences
			if b == 27 && i+1 < len(chunk) && chunk[i+1] == 91 {

				// минимум ESC [ X
				if i+2 >= len(chunk) {
					continue
				}

				code := chunk[i+2]

				// ===== стрелки =====
				if code >= 65 && code <= 68 {
					i += 2

					switch code {
					case 65: // ↑
						if e.row > 0 {
							e.row--
							if e.col > len(e.lines[e.row]) {
								e.col = len(e.lines[e.row])
							}
						}

					case 66: // ↓
						if e.row < len(e.lines)-1 {
							e.row++
							if e.col > len(e.lines[e.row]) {
								e.col = len(e.lines[e.row])
							}
						}

					case 67: // →
						if e.col < len(e.lines[e.row]) {
							e.col++
						}

					case 68: // ←
						if e.col > 0 {
							e.col--
						}
					}

					e.redraw()
					continue
				}

				// ===== HOME / END =====
				if code == 'H' { // HOME
					e.col = 0
					i += 2
					e.redraw()
					continue
				}

				if code == 'F' { // END
					e.col = len(e.lines[e.row])
					i += 2
					e.redraw()
					continue
				}

				// ===== ESC [ number ~ =====
				if i+3 < len(chunk) && chunk[i+3] == '~' {
					switch code {
					case '2': // INS
						// игнорируем
					case '3': // DELETE
						if e.col < len(e.lines[e.row]) {
							line := e.lines[e.row]
							e.lines[e.row] = line[:e.col] + line[e.col+1:]
						}
					case '5': // PGUP
						e.row = 0
						if e.col > len(e.lines[e.row]) {
							e.col = len(e.lines[e.row])
						}
					case '6': // PGDN
						e.row = len(e.lines) - 1
						if e.col > len(e.lines[e.row]) {
							e.col = len(e.lines[e.row])
						}
					}

					i += 3
					e.redraw()
					continue
				}

				// ВСЁ остальное — игнор
				continue
			}

			// обычный символ
			if b >= 32 && b <= 126 {
				line := e.lines[e.row]
				e.lines[e.row] = line[:e.col] + string(b) + line[e.col:]
				e.col++
				e.redraw()
			}
		}
	}
}


func escapeMode(stdinChan <-chan []byte) bool {
	// Переходим в альтернативный буфер — экран сессии сохраняется терминалом
	atomic.StoreInt32(&inEscapeMode, 1)
	fmt.Print("\033[?1049h\033[H\033[2J")

	// restore: возвращаем основной буфер — терминал сам восстанавливает экран как был
	restore := func() {
		atomic.StoreInt32(&inEscapeMode, 0)
		fmt.Print("\033[?1049l")
	}

	for {
		// Используем уже готовую функцию, которая умеет в стрелочки и редактирование
		line := readLineInteractive(stdinChan, &escapeHistory)
		cmd := strings.TrimSpace(line)

		if cmd == "" {
			continue
		}

		// Добавляем в историю, если команда не пустая
		escapeHistory = append(escapeHistory, cmd)

		parts := strings.Fields(cmd)
		baseCmd := strings.ToLower(parts[0])

		switch baseCmd {
		case "reload":
			reloadConfig()
		
		case "savehost":
			var alias string
				if len(parts) >= 2 {
				alias = parts[1]
			}
				if addr == "" {
				fmt.Printf("%sNo active host%s\r\n", ColorRed, ColorReset)
				break
			}

			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				fmt.Printf("%sInvalid address%s\r\n", ColorRed, ColorReset)
				break
			}
		
			cfg := HostConfig{
				Alias:         alias,
				Host:          host,
				Port:          port,
				KeepAlive:     int(keepaliveDuration.Seconds()),
				KeepAliveType: keepaliveType,
				WaitTimeout:   currentWaitTimeout,
			}
		
			existing, ok := findHostConfig(addr)
			if ok {
				cfg.OnConnect = existing.OnConnect
			}
				err = saveHostToConfig(cfg)
			if err != nil {
				fmt.Printf("%sFailed to save host: %v%s\r\n", ColorRed, err, ColorReset)
				break
			}
				if alias == "" {
				fmt.Printf("%sHost saved: %s%s\r\n", ColorGreen, addr, ColorReset)
			} else {
				fmt.Printf("%sHost saved as alias '%s'%s\r\n", ColorGreen, alias, ColorReset)
			}
		
		case "q", "quit", "exit":
			fmt.Printf("%sBye%s\r\n", ColorCyan, ColorReset)
			if conn != nil {
				c := conn
				conn = nil
				c.Close()
			}
			return true
		case "resume", "c":
			restore()
			return false
		case "status":
			if conn != nil {
				fmt.Printf("%sConnected to %s%s\r\n", ColorGreen, addr, ColorReset)
			} else {
				fmt.Printf("%sNot connected%s\r\n", ColorRed, ColorReset)
			}
			if keepaliveDuration > 0 {
				fmt.Printf("Anti-idle keepalive: %v (Type: %s)\r\n", keepaliveDuration, keepaliveType)
			} else {
				fmt.Print("Anti-idle keepalive: disabled\r\n")
			}

		case "close":
			if conn != nil {
				c := conn
				conn = nil
				c.Close()
			}
			fmt.Printf("%sConnection closed%s\r\n", ColorCyan, ColorReset)
				
		case "reconnect":
			if conn != nil {
				c := conn
				conn = nil
				c.Close()
			}
			select {
				case <-serverDisconnect:
					default:
				}

			fmt.Printf("%sReconnecting...%s\r\n", ColorCyan, ColorReset)
			if err := connect(); err != nil {
				fmt.Printf("%sReconnect failed: %v%s\r\n", ColorRed, err, ColorReset)
			} else {
				fmt.Printf("%sReconnected%s\r\n", ColorGreen, ColorReset)
			}
			restore()
			return false

		case "connect":
			if len(parts) < 2 {
				fmt.Printf("%sUsage: connect <host_or_alias>[:port]%s\r\n", ColorYellow, ColorReset)
				break
			}
			if conn != nil {
				c := conn
				conn = nil
				c.Close()
				fmt.Printf("%sClosed previous connection.%s\r\n", ColorCyan, ColorReset)
			}

			select {
				case <-serverDisconnect:
					default:
			}

			newTarget := parts[1]
			var commandsToRun []string
			var matchedConfig *HostConfig

			if cfg, ok := findHostConfig(newTarget); ok {
				matchedConfig = &cfg
				host := cfg.Host
				port := "23"
				if cfg.Port != "" {
					port = cfg.Port
				}
				addr = host + ":" + port
				commandsToRun = append(commandsToRun, expandCommands(cfg.OnConnect)...)
			} else {
				if !strings.Contains(newTarget, ":") {
					newTarget = newTarget + ":23"
				}
				addr = newTarget
			}

			applyHostConfig(matchedConfig)

			fmt.Printf("%sConnecting to %s...%s\r\n", ColorCyan, addr, ColorReset)
			if err := connect(); err != nil {
				fmt.Printf("%sConnection failed: %v%s\r\n", ColorRed, err, ColorReset)
			} else {
				fmt.Printf("%sConnected to %s%s\r\n", ColorGreen, addr, ColorReset)
				if len(commandsToRun) > 0 {
					go runOnConnectCommands(commandsToRun)
				}
			}
			restore()
			return false

		case "keepalive":
			if len(parts) < 2 {
				if keepaliveDuration > 0 {
					fmt.Printf("%sCurrent keepalive: %v (Type: %s)%s\r\n", ColorGreen, keepaliveDuration, keepaliveType, ColorReset)
				} else {
					fmt.Printf("%sAnti-idle is currently disabled.%s\r\n", ColorYellow, ColorReset)
				}
				break
			}

			sec, err := strconv.Atoi(parts[1])
			if err != nil || sec < 0 {
				fmt.Print("Invalid interval. Usage: keepalive <seconds>\r\n")
				break
			}

			keepaliveDuration = time.Duration(sec) * time.Second

			if idleTimer != nil {
				if !idleTimer.Stop() {
					select {
						case <-idleTimer.C:
							default:
						}
					}
				}

			if sec == 0 {
				idleTimer = nil
				timerCh = nil
				fmt.Print("Anti-idle disabled.\r\n")
			} else {
				if idleTimer == nil {
					idleTimer = time.NewTimer(keepaliveDuration)
				} else {
					idleTimer.Reset(keepaliveDuration)
				}
				timerCh = idleTimer.C
				fmt.Printf("Anti-idle set to %d seconds.\r\n", sec)
			}

		case "onconnect":
			if addr == "" {
				fmt.Printf("%sNo active host%s\r\n", ColorRed, ColorReset)
				break
			}

			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				fmt.Printf("%sInvalid address%s\r\n", ColorRed, ColorReset)
				break
			}

			if len(parts) < 2 {
				fmt.Printf("%sUsage:%s onconnect edit | clear | show\r\n", ColorYellow, ColorReset)
				break
			}

			sub := strings.ToLower(parts[1])

			switch sub {
				case "clear":
					cfg, ok := findHostConfig(addr)
					if !ok {
						fmt.Printf("%sHost not found%s\r\n", ColorRed, ColorReset)
						break
					}

					cfg.OnConnect = nil
					err := saveHostToConfig(cfg)
					if err != nil {
						fmt.Printf("%sFailed to update config: %v%s\r\n", ColorRed, err, ColorReset)
						break
					}

					fmt.Printf("%sCleared on_connect commands%s\r\n", ColorGreen, ColorReset)

				case "show":
					cfg, ok := findHostConfig(addr)
					if !ok || len(cfg.OnConnect) == 0 {
						fmt.Printf("%sNo on_connect commands%s\r\n", ColorYellow, ColorReset)
						break
					}

					fmt.Printf("%sOn-connect commands:%s\r\n", ColorCyan, ColorReset)

					for i, c := range cfg.OnConnect {
						fmt.Printf("  %d: %s\r\n", i+1, c)
					}
				
				case "edit":
					cfg, ok := findHostConfig(addr)
					var initial []string
					if ok {
						initial = expandForEdit(cfg.OnConnect)
					} else {
						cfg = HostConfig{
							Host:          host,
							Port:          port,
							KeepAlive:     int(keepaliveDuration.Seconds()),
							KeepAliveType: keepaliveType,
							WaitTimeout:   currentWaitTimeout,
						}
						initial = []string{""}
					}

					cmds, ok := runEditor(stdinChan, initial)
					if !ok {
						break
					}
					
					cfg.OnConnect = processEditorLines(cmds)

					saveHostToConfig(cfg)
					fmt.Printf("%sOn-connect updated%s\r\n", ColorGreen, ColorReset)

				default:
						fmt.Printf("%sUnknown subcommand%s\r\n", ColorRed, ColorReset)
				}
				
		case "keys":
			handleKeysCommand(parts, stdinChan)
				
		case "help", "?":
			fmt.Printf("%sAvailable commands:%s\r\n", ColorYellow, ColorReset)
			fmt.Printf("  %ssavehost [alias]%s             - Save current host to config\r\n", ColorGreen, ColorReset)
			fmt.Printf("  %sresume, c%s                    - Resume session\r\n", ColorGreen, ColorReset)
			fmt.Printf("  %sstatus%s                       - Show connection status\r\n", ColorGreen, ColorReset)
			fmt.Printf("  %sconnect <host_or_alias>[:port]%s - Connect to a new host\r\n", ColorGreen, ColorReset)
			fmt.Printf("  %sclose%s                        - Close current connection\r\n", ColorGreen, ColorReset)
			fmt.Printf("  %sreconnect%s                    - Reconnect\r\n", ColorGreen, ColorReset)
			fmt.Printf("  %skeepalive [seconds]%s          - Set keepalive interval\r\n", ColorGreen, ColorReset)
			fmt.Printf("  %sonconnect show%s               - Show secret commands\r\n", ColorGreen, ColorReset)
			fmt.Printf("  %sonconnect edit%s               - Edit secret commands\r\n", ColorGreen, ColorReset)
			fmt.Printf("  %sonconnect clear%s              - Remove secret commands\r\n", ColorGreen, ColorReset)
			fmt.Printf("  %skeys import%s                  - Import master key\r\n", ColorGreen, ColorReset)
			fmt.Printf("  %skeys export%s                  - Export master key\r\n", ColorGreen, ColorReset)
			fmt.Printf("  %squit, exit, q%s                - Exit\r\n", ColorGreen, ColorReset)

		default:
			fmt.Printf("%sUnknown command '%s'.%s\r\n", ColorRed, baseCmd, ColorReset)
		}
	}
}

func readerLoop(c net.Conn) {
	var tBuf []byte
	buf := make([]byte, 4096)

	for {
		n, err := c.Read(buf)
		if err != nil {
			if conn == c {
				fmt.Printf("\r\n%sConnection closed by remote host.%s\r\n", ColorRed, ColorReset)
				conn = nil
				serverDisconnect <- struct{}{}
			}
			return
		}

		tBuf = append(tBuf, buf[:n]...)
		
		// ЗАЩИТА ОТ ИСЧЕРПАНИЯ ПАМЯТИ
		// Если накопилось больше 1 Мегабайта неразобранных данных (например, нет IAC SE)
		if len(tBuf) > 1024*1024 {
			fmt.Fprintf(os.Stderr, "\r\n%sWarning: receive buffer overflow, discarding data%s\r\n", ColorYellow, ColorReset)
			tBuf = nil // Очищаем буфер
			continue   // Переходим к следующему чтению
		}

		i := 0
		var textChunk []byte

		for i < len(tBuf) {
			if tBuf[i] == IAC {
				if len(textChunk) > 0 {
					out := string(textChunk)

					lastOutput.Write([]byte(out))

					if atomic.LoadInt32(&inEscapeMode) == 0 {
						os.Stdout.WriteString(applyColors(out))
					}
					textChunk = nil
				}

				if i+1 >= len(tBuf) {
					break
				}
				cmd := tBuf[i+1]
				if cmd == IAC {
					textChunk = append(textChunk, IAC)
					i += 2
					continue
				}
				if cmd == DO || cmd == DONT || cmd == WILL || cmd == WONT {
					if i+2 >= len(tBuf) {
						break
					}
					handleIAC(c, tBuf[i:i+3])
					i += 3
					continue
				}
				if cmd == SB {
					found := false
					for j := i + 2; j < len(tBuf)-1; j++ {
						if tBuf[j] == IAC && tBuf[j+1] == SE {
							i = j + 2
							found = true
							break
						}
					}
					if !found {
						break
					}
					continue
				}
				i += 2
			} else {
				textChunk = append(textChunk, tBuf[i])
				i++
			}
		}

		if len(textChunk) > 0 {
			out := string(textChunk)

			lastOutput.Write([]byte(out))

			if atomic.LoadInt32(&inEscapeMode) == 0 {
				os.Stdout.WriteString(applyColors(out))
			}
		}

		tBuf = tBuf[i:]
	}
}

func stdinReader(stdinChan chan []byte) {
	buf := make([]byte, 128)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			stdinChan <- data
		}
	}
}

func watchWindowSize() {
	return
}

func main() {
	exePath, _ := os.Executable()
	configPath = filepath.Join(filepath.Dir(exePath), "telnet.json")
	// Читаем JSON-дефолты ДО парсинга флагов, чтобы определить приоритеты.
	// Приоритет: хост-конфиг > явный флаг CLI > defaults из JSON > встроенные значения.
	jsonDefaults := loadConfigDefaults()

	builtinKeepalive := 120
	builtinWaitTimeout := 10
	builtinKeepaliveType := "space_bs"

	keepaliveFlag := flag.Int("keepalive", builtinKeepalive, "Keepalive interval in seconds (0 to disable)")
	keepaliveTypeFlag := flag.String("keepalive_type", builtinKeepaliveType, "Keepalive type: space_bs, 0x13, 0x00")

	if len(os.Args) > 1 {
		switch os.Args[1] {
			case "keys":
				handleKeysCommand(os.Args[1:], nil)
				return
			}
		}
		
	flag.Parse()

	// Определяем, какие флаги были переданы явно
	cliKeepaliveSet := false
	cliKeepaliveTypeSet := false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "keepalive":
			cliKeepaliveSet = true
		case "keepalive_type":
			cliKeepaliveTypeSet = true
		}
	})

	// keepalive: явный CLI > JSON defaults > встроенный
	if cliKeepaliveSet {
		globalKeepalive = *keepaliveFlag
	} else if jsonDefaults.KeepAlive != 0 {
		globalKeepalive = jsonDefaults.KeepAlive
	} else {
		globalKeepalive = builtinKeepalive
	}

	// keepalive_type: явный CLI > JSON defaults > встроенный
	if cliKeepaliveTypeSet {
		globalKeepaliveType = *keepaliveTypeFlag
	} else if jsonDefaults.KeepAliveType != "" {
		globalKeepaliveType = jsonDefaults.KeepAliveType
	} else {
		globalKeepaliveType = builtinKeepaliveType
	}
	
	if jsonDefaults.WaitTimeout != 0 {
		globalWaitTimeout = jsonDefaults.WaitTimeout
	} else {
		globalWaitTimeout = builtinWaitTimeout
	}

	if flag.NArg() < 1 {
		fmt.Println("Usage:\n  telnet [cmd|options] <host_or_alias> [port]")
		fmt.Println("\ncmd:")
		fmt.Println("\n keys export | import | delete | status")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		return
	}

	loadFullConfig()
	configAliases, configByHost = buildIndexesFromCache()
	buildColorRulesFromCache()
	validateMasterKeyFromConfig()
	
	inputTarget := flag.Arg(0)
	port := "23"
	if flag.NArg() >= 2 {
		port = flag.Arg(1)
	}

	var commandsToRun []string
	var matchedConfig *HostConfig

	if cfg, ok := findHostConfig(inputTarget); ok {
		matchedConfig = &cfg
		host := cfg.Host
		if cfg.Port != "" {
			port = cfg.Port
		}
		addr = host + ":" + port
		commandsToRun = append(commandsToRun, expandCommands(cfg.OnConnect)...)
	} else {
		if strings.Contains(inputTarget, ":") {
			addr = inputTarget
		} else {
			addr = inputTarget + ":" + port
		}
	}

	applyHostConfig(matchedConfig)

	if err := connect(); err != nil {
		fmt.Printf("%sConnection error: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	enableRaw()

	defer func() {
		term.Restore(int(os.Stdin.Fd()), oldState)
		if conn != nil {
			conn.Close()
		}
		fmt.Println()
	}()

	fmt.Printf("%sConnected to %s%s\r\n", ColorGreen, addr, ColorReset)
	fmt.Printf("%sEscape character is 'CTRL+]'.%s\r\n", ColorCyan, ColorReset)

	if len(commandsToRun) > 0 {
		go runOnConnectCommands(commandsToRun)
	}

	stdinChan := make(chan []byte, 32)
	go stdinReader(stdinChan)
	go watchWindowSize()

	if idleTimer != nil {
		defer idleTimer.Stop()
	}

	for {
		select {
		case <-serverDisconnect:
			return

		case <-timerCh:
			if conn != nil {
				var payload []byte
				switch keepaliveType {
				case "0x00":
					payload = []byte{0}
				case "0x13":
					payload = []byte("\r\n")
				case "space_bs":
					fallthrough
				default:
					// Пробел (0x20) и Backspace (0x08)
					payload = []byte{' ', 0x08}
				}

				_, err := conn.Write(payload)
				if err != nil {
					fmt.Printf("\r\n%sWrite error: connection lost.%s\r\n", ColorRed, ColorReset)
					conn.Close()
					conn = nil
				}
			}
			if idleTimer != nil {
				idleTimer.Reset(keepaliveDuration)
			}

		case data := <-stdinChan:
			escapePressed := false
			for i := 0; i < len(data); i++ {
				if data[i] == ESCAPE {
					escapePressed = true
					break
				}
			}

			if escapePressed {
				if shouldExit := escapeMode(stdinChan); shouldExit {
					return
				}
				continue
			}

			if atomic.LoadInt32(&inputLocked) == 1 {
				continue
			}
			
			if idleTimer != nil {
				if !idleTimer.Stop() {
					select {
					case <-idleTimer.C:
					default:
					}
				}
				idleTimer.Reset(keepaliveDuration)
			}

			if conn != nil {
				_, err := conn.Write(normalizeInput(data))
				if err != nil {
					fmt.Printf("\r\n%sWrite error: connection lost.%s\r\n", ColorRed, ColorReset)
					conn.Close()
					conn = nil
				}
			}
		}
	}
}
