// Command p0 builds reviewed local services and runs mandatory real-adapter tests.
package main

import (
	"archive/tar"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type artifact struct{ Name, Version, Source, SHA256 string }

func run(ctx context.Context, dir string, env []string, log io.Writer, name string, args ...string) error {
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	c.Env = env
	c.Stdout = log
	c.Stderr = log
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s: %w (see build/service logs)", name, err)
	}
	return nil
}
func extract(ctx context.Context, a artifact, dir string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, "GET", a.Source, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mayi-p0-source-build")
	r, err := client.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("source download: %s", r.Status)
	}
	archive, err := os.CreateTemp(dir, "source-*")
	if err != nil {
		return err
	}
	defer os.Remove(archive.Name())
	defer archive.Close()
	hash := sha256.New()
	if _, err = io.Copy(io.MultiWriter(archive, hash), io.LimitReader(r.Body, 150<<20)); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != a.SHA256 {
		return fmt.Errorf("%s source digest mismatch", a.Name)
	}
	if _, err = archive.Seek(0, 0); err != nil {
		return err
	}
	var reader io.Reader = bzip2.NewReader(archive)
	if a.Name == "openbao" {
		gz, err := gzip.NewReader(archive)
		if err != nil {
			return err
		}
		defer gz.Close()
		reader = gz
	}
	tr := tar.NewReader(reader)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		_, rel, ok := strings.Cut(h.Name, "/")
		if !ok || rel == "" {
			continue
		}
		rel = filepath.Clean(rel)
		if !filepath.IsLocal(rel) {
			return fmt.Errorf("unsafe source path")
		}
		path := filepath.Join(dir, "source", rel)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(h.Mode)&0755)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			// Preserve source timestamps for reproducible incremental builds.
			if !h.ModTime.IsZero() {
				if err := os.Chtimes(path, h.ModTime, h.ModTime); err != nil {
					return err
				}
			}
		case tar.TypeSymlink, tar.TypeLink:
			if a.Name == "openbao" && rel == "CLAUDE.md" {
				continue
			}
			return fmt.Errorf("unsupported source link: %s", h.Name)
		}
	}
	return nil
}
func port() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return fmt.Sprint(l.Addr().(*net.TCPAddr).Port), nil
}
func start(ctx context.Context, env []string, log *os.File, name string, args ...string) (*exec.Cmd, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Env = env
	c.Stdout = log
	c.Stderr = log
	if err := c.Start(); err != nil {
		return nil, err
	}
	return c, nil
}
func verifyBuildModules(ctx context.Context, root, source string, env []string) error {
	b, err := os.ReadFile(filepath.Join(root, "docs/p0/openbao-components.json"))
	if err != nil {
		return err
	}
	var components []struct{ Name, Version string }
	if err := json.Unmarshal(b, &components); err != nil {
		return err
	}
	approved := map[string]bool{}
	for _, c := range components {
		approved[c.Name+"@"+c.Version] = true
	}
	cmd := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-deps", "-json", ".")
	cmd.Dir = source
	cmd.Env = env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	data, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("resolve service graph: %w: %s", err, stderr.String())
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	for {
		var pkg struct {
			Module *struct {
				Path, Version string
				Main          bool
				Replace       *struct{ Dir string }
			}
		}
		err := decoder.Decode(&pkg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		m := pkg.Module
		if m == nil {
			continue
		}
		version := m.Version
		if m.Main || m.Replace != nil {
			if m.Replace != nil {
				rel, err := filepath.Rel(source, m.Replace.Dir)
				if err != nil || !filepath.IsLocal(rel) {
					return fmt.Errorf("service replacement escapes source")
				}
			}
			version = "v2.7.1"
		}
		if !approved[m.Path+"@"+version] {
			return fmt.Errorf("unreviewed compiled service component %s@%s", m.Path, version)
		}
	}
	return nil
}
func main() {
	if err := mainRun(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func mainRun() error {
	cache := flag.String("cache", filepath.Join(os.TempDir(), "mayi-p0-services"), "private service build cache")
	flag.Parse()
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return fmt.Errorf("unsupported P0 platform")
	}
	// Check policies before downloading, compiling or executing any service.
	if err := run(ctx, root, os.Environ(), os.Stdout, "go", "run", "./tools/checks", "-only", "licenses"); err != nil {
		return err
	}
	b, err := os.ReadFile("tools/services.json")
	if err != nil {
		return err
	}
	var inventory struct{ Artifacts []artifact }
	if err := json.Unmarshal(b, &inventory); err != nil {
		return err
	}
	if err := os.MkdirAll(*cache, 0700); err != nil {
		return err
	}
	if err := os.Chmod(*cache, 0700); err != nil {
		return err
	}
	home := filepath.Join(*cache, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		return err
	}
	// An explicit allowlist keeps cloud credentials and unrelated service settings
	// out of both builds and local service processes.
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TMPDIR=" + os.TempDir(), "GOTOOLCHAIN=local", "GOWORK=off", "CGO_ENABLED=0", "GOMAXPROCS=3"}
	for _, key := range []string{"GOCACHE", "GOPATH", "GOROOT", "GOPROXY", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		value := os.Getenv(key)
		if value == "" && (key == "GOCACHE" || key == "GOPATH" || key == "GOROOT") {
			command := exec.CommandContext(ctx, "go", "env", key)
			data, err := command.Output()
			if err != nil {
				return err
			}
			value = strings.TrimSpace(string(data))
		}
		if value != "" {
			env = append(env, key+"="+value)
		}
	}
	paths := map[string]string{}
	for _, a := range inventory.Artifacts {
		profile := "p0-v2"
		dir := filepath.Join(*cache, a.Name+"-"+a.Version+"-"+a.SHA256[:12]+"-"+runtime.GOOS+"-"+runtime.GOARCH+"-"+profile)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		binary := filepath.Join(dir, "bin", a.Name)
		if a.Name == "postgresql" {
			binary = filepath.Join(dir, "bin", "postgres")
		}
		paths[a.Name] = binary
		if _, err := os.Stat(binary); err == nil {
			continue
		}
		fmt.Println("Building reviewed", a.Name, a.Version)
		if err := extract(ctx, a, dir); err != nil {
			return err
		}
		log, err := os.Create(filepath.Join(dir, "build.log"))
		if err != nil {
			return err
		}
		source := filepath.Join(dir, "source")
		if a.Name == "postgresql" {
			pgEnv := append(append([]string{}, env...), "MKDIR_P=mkdir -p", "INSTALL=/usr/bin/install -c")
			err = run(ctx, source, pgEnv, log, "./configure", "--prefix="+dir, "--without-icu", "--without-readline", "--without-zlib", "--without-lz4", "--without-zstd", "--disable-nls", "--with-system-tzdata=/usr/share/zoneinfo")
			if err == nil {
				err = run(ctx, source, env, log, "make", "-j3", "MKDIR_P=mkdir -p", "CUSTOM_INSTALL=/usr/bin/install -c")
			}
			if err == nil {
				err = run(ctx, source, env, log, "make", "install", "MKDIR_P=mkdir -p", "CUSTOM_INSTALL=/usr/bin/install -c")
			}
		} else {
			if err = verifyBuildModules(ctx, root, source, env); err == nil {
				err = run(ctx, source, env, log, "go", "build", "-mod=readonly", "-p=3", "-o", binary, ".")
			}
		}
		_ = log.Close()
		if err != nil {
			return fmt.Errorf("%s: %w; log %s", a.Name, err, log.Name())
		}
	}
	session, err := os.MkdirTemp("/tmp", "mayi-p0-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(session)
	socket := filepath.Join(session, "socket")
	if err := os.Mkdir(socket, 0700); err != nil {
		return err
	}
	pglog, err := os.Create(filepath.Join(session, "postgres.log"))
	if err != nil {
		return err
	}
	defer pglog.Close()
	pgdir := filepath.Dir(paths["postgresql"])
	if err := run(ctx, session, env, pglog, filepath.Join(pgdir, "initdb"), "-D", filepath.Join(session, "data"), "-A", "trust", "-U", "mayi_test", "--no-locale"); err != nil {
		return err
	}
	pg, err := start(ctx, env, pglog, paths["postgresql"], "-D", filepath.Join(session, "data"), "-k", socket, "-c", "listen_addresses=", "-c", "fsync=on")
	if err != nil {
		return err
	}
	defer func() { _ = pg.Process.Signal(os.Interrupt); _ = pg.Wait() }()
	for n := 0; n < 100; n++ {
		if err = run(ctx, session, env, io.Discard, filepath.Join(pgdir, "pg_isready"), "-h", socket, "-U", "mayi_test"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("PostgreSQL did not start")
	}
	baolog, err := os.Create(filepath.Join(session, "openbao.log"))
	if err != nil {
		return err
	}
	defer baolog.Close()
	address, err := port()
	if err != nil {
		return err
	}
	url := "http://127.0.0.1:" + address
	bao, err := start(ctx, env, baolog, paths["openbao"], "server", "-dev", "-dev-root-token-id=mayi-isolated-test-only", "-dev-listen-address=127.0.0.1:"+address)
	if err != nil {
		return err
	}
	defer func() { _ = bao.Process.Signal(os.Interrupt); _ = bao.Wait() }()
	client := &http.Client{Timeout: time.Second}
	ready := false
	for n := 0; n < 200; n++ {
		r, e := client.Get(url + "/v1/sys/health")
		if e == nil {
			_ = r.Body.Close()
			if r.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return fmt.Errorf("OpenBao did not start; log %s", baolog.Name())
	}
	fmt.Println("Running real PostgreSQL and OpenBao P0 tests")
	testenv := make([]string, 0, len(env)+5)
	for _, item := range env {
		if !strings.HasPrefix(item, "CGO_ENABLED=") {
			testenv = append(testenv, item)
		}
	}
	testenv = append(testenv, "CGO_ENABLED=1", "GOFLAGS=-mod=readonly", "MAYI_P0_REQUIRED=1", "MAYI_P0_POSTGRES=host="+socket+" user=mayi_test dbname=postgres sslmode=disable", "MAYI_P0_TRANSIT="+url, "MAYI_P0_TRANSIT_TOKEN=mayi-isolated-test-only")
	return run(ctx, root, testenv, os.Stdout, "go", "test", "-race", "-count=1", "-v", "./tests/integration")
}
