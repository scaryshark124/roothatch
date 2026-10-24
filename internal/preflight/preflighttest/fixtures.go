// Package preflighttest builds small synthetic root trees for preflight tests.
// It writes only beneath caller-supplied temporary directories and generates
// ELF headers in memory; it never copies or executes host binaries.
package preflighttest

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// ELF machine numbers used by the fixtures.
const (
	EMX8664   = 62
	EMAArch64 = 183
	// Loader is the x86-64 glibc PT_INTERP path.
	Loader = "/lib64/ld-linux-x86-64.so.2"
)

// ELF returns a minimal little-endian ELF64 ET_DYN image for machine. It has
// one PT_LOAD program header and, when interp is non-empty, a PT_INTERP header
// naming interp.
func ELF(machine uint16, interp string) []byte {
	phnum := 1
	if interp != "" {
		phnum = 2
	}
	const ehsize, phentsize = 64, 56
	dataOff := ehsize + phentsize*phnum
	b := make([]byte, dataOff+len(interp)+1)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1 // ELFCLASS64, ELFDATA2LSB, EV_CURRENT
	le := binary.LittleEndian
	le.PutUint16(b[16:], 3) // ET_DYN
	le.PutUint16(b[18:], machine)
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[32:], ehsize) // e_phoff
	le.PutUint16(b[52:], ehsize)
	le.PutUint16(b[54:], phentsize)
	le.PutUint16(b[56:], uint16(phnum))
	ph := b[ehsize:]
	le.PutUint32(ph[0:], 1) // PT_LOAD
	le.PutUint64(ph[32:], uint64(len(b)))
	if interp != "" {
		ph = b[ehsize+phentsize:]
		le.PutUint32(ph[0:], 3) // PT_INTERP
		le.PutUint64(ph[8:], uint64(dataOff))
		le.PutUint64(ph[32:], uint64(len(interp)+1))
		copy(b[dataOff:], interp)
	}
	return b
}

// Kind is a fixture entry type.
type Kind int

// Fixture entry kinds.
const (
	KindFile Kind = iota
	KindDir
	KindLink
	KindFIFO
)

// Entry is one object to create inside a fixture root.
type Entry struct {
	Path   string // slash-separated, relative to the root
	Kind   Kind
	Data   []byte
	Target string // symlink target, written literally
}

// File, Dir, Link and FIFO construct entries.
func File(p string, data []byte) Entry { return Entry{Path: p, Kind: KindFile, Data: data} }
func Dir(p string) Entry               { return Entry{Path: p, Kind: KindDir} }
func Link(p, target string) Entry      { return Entry{Path: p, Kind: KindLink, Target: target} }
func FIFO(p string) Entry              { return Entry{Path: p, Kind: KindFIFO} }

// Build creates entries beneath root, creating real parent directories as
// needed. Parents must not traverse symlinks created by earlier entries.
func Build(root string, entries ...Entry) error {
	for _, e := range entries {
		p := filepath.Join(root, filepath.FromSlash(e.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		var err error
		switch e.Kind {
		case KindFile:
			err = os.WriteFile(p, e.Data, 0o755)
		case KindDir:
			err = os.MkdirAll(p, 0o755)
		case KindLink:
			err = os.Symlink(e.Target, p)
		case KindFIFO:
			err = syscall.Mkfifo(p, 0o644)
		default:
			err = fmt.Errorf("unknown kind %d", e.Kind)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Digest returns a deterministic description of the tree at root: each
// entry's relative path, permission/type mode, regular-file SHA-256 and
// literal symlink target. It never follows symlinks or opens special files,
// and it deliberately excludes timestamps.
func Digest(root string) (string, error) {
	var lines []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		line := fmt.Sprintf("%s %v", filepath.ToSlash(rel), info.Mode())
		switch {
		case info.Mode().Type() == fs.ModeSymlink:
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			line += " -> " + t
		case info.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			line += fmt.Sprintf(" sha256=%x", sha256.Sum256(data))
		}
		lines = append(lines, line)
		return nil
	})
	sort.Strings(lines)
	return strings.Join(lines, "\n"), err
}

// Fixture is a named synthetic root with the expected finding codes; an
// empty Want means every limited check must pass.
type Fixture struct {
	Name    string
	Entries []Entry
	Want    []string
	Static  bool // expected to pass as a static (no PT_INTERP) shell
}

func mergedUsr(extra ...Entry) []Entry {
	return append([]Entry{
		Link("bin", "usr/bin"), Link("lib", "usr/lib"), Link("lib64", "usr/lib64"),
		Dir("usr/bin"), Dir("usr/lib"), Dir("usr/lib64"),
	}, extra...)
}

func loaderFile() Entry {
	return File("usr/lib64/ld-linux-x86-64.so.2", []byte("synthetic loader placeholder"))
}

func shell() Entry { return File("usr/bin/sh", ELF(EMX8664, Loader)) }

// Catalog returns every acceptance and robustness fixture.
func Catalog() []Fixture {
	debian := func(extra ...Entry) []Entry {
		return append([]Entry{
			Link("bin", "usr/bin"), Link("lib", "usr/lib"), Dir("lib64"),
			shell(), Dir("usr/lib/x86_64-linux-gnu"),
			Link("lib64/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
		}, extra...)
	}
	elf32 := ELF(EMX8664, Loader)
	elf32[4] = 1
	bigEndian := ELF(EMX8664, Loader)
	bigEndian[5] = 2
	return []Fixture{
		{Name: "healthy_merged_usr", Entries: mergedUsr(shell(), loaderFile())},
		{Name: "missing_shell", Entries: mergedUsr(loaderFile()), Want: []string{"shell_missing"}},
		{Name: "dangling_shell_link", Entries: mergedUsr(Link("usr/bin/sh", "dash"), loaderFile()), Want: []string{"shell_missing"}},
		{Name: "missing_interp", Entries: mergedUsr(shell()), Want: []string{"interp_missing"}},
		{Name: "arch_aarch64", Entries: mergedUsr(File("usr/bin/sh", ELF(EMAArch64, "/lib/ld-linux-aarch64.so.1"))), Want: []string{"arch_unsupported"}},
		{Name: "arch_elf32", Entries: mergedUsr(File("usr/bin/sh", elf32), loaderFile()), Want: []string{"arch_unsupported"}},
		{Name: "arch_big_endian", Entries: mergedUsr(File("usr/bin/sh", bigEndian), loaderFile()), Want: []string{"arch_unsupported"}},
		{Name: "escape_relative_shell", Entries: mergedUsr(Link("usr/bin/sh", "../../../../bin/sh")), Want: []string{"symlink_escape"}},
		{Name: "escape_link_chain", Entries: mergedUsr(Link("usr/bin/sh", "dash"), Link("usr/bin/dash", "../../../outside/sh")), Want: []string{"symlink_escape"}},
		{Name: "escape_ancestor_dir", Entries: []Entry{Link("bin", "../usr/bin"), shell(), loaderFile()}, Want: []string{"symlink_escape"}},
		{Name: "escape_absolute_dotdot", Entries: []Entry{Dir("bin"), Link("bin/sh", "/../../bin/sh")}, Want: []string{"symlink_escape"}},
		{Name: "escape_interp", Entries: []Entry{
			Link("bin", "usr/bin"), shell(), Dir("lib64"),
			Link("lib64/ld-linux-x86-64.so.2", "../../../../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
		}, Want: []string{"symlink_escape"}},
		{Name: "debian_absolute_loader", Entries: debian(File("usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", []byte("synthetic loader")))},
		{Name: "absolute_loader_target_only_on_host", Entries: debian(), Want: []string{"interp_missing"}},
		{Name: "static_shell", Entries: mergedUsr(File("usr/bin/sh", ELF(EMX8664, ""))), Static: true},
		{Name: "loop_self", Entries: mergedUsr(Link("usr/bin/sh", "sh")), Want: []string{"symlink_loop"}},
		{Name: "loop_pair", Entries: mergedUsr(Link("usr/bin/sh", "a"), Link("usr/bin/a", "/bin/sh")), Want: []string{"symlink_loop"}},
		{Name: "loop_dir", Entries: []Entry{Link("bin", "bin")}, Want: []string{"symlink_loop"}},
		{Name: "loop_interp", Entries: mergedUsr(shell(), Link("usr/lib64/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2")), Want: []string{"symlink_loop"}},
		{Name: "shell_fifo", Entries: mergedUsr(FIFO("usr/bin/sh")), Want: []string{"shell_not_regular"}},
		{Name: "shell_directory", Entries: mergedUsr(Dir("usr/bin/sh")), Want: []string{"shell_not_regular"}},
		{Name: "interp_fifo", Entries: mergedUsr(shell(), FIFO("usr/lib64/ld-linux-x86-64.so.2")), Want: []string{"interp_not_regular"}},
		{Name: "shell_script", Entries: mergedUsr(File("usr/bin/sh", []byte("#!/bin/dash\necho hi\n"))), Want: []string{"elf_invalid"}},
		{Name: "shell_truncated_elf", Entries: mergedUsr(File("usr/bin/sh", ELF(EMX8664, Loader)[:30])), Want: []string{"elf_invalid"}},
		{Name: "shell_empty", Entries: mergedUsr(File("usr/bin/sh", nil)), Want: []string{"elf_invalid"}},
		// A trailing "/" (or "/.") after a non-directory is ENOTDIR on Linux.
		{Name: "shell_link_trailing_slash", Entries: mergedUsr(File("usr/bin/dash", ELF(EMX8664, Loader)), Link("usr/bin/sh", "dash/"), loaderFile()), Want: []string{"shell_missing"}},
		{Name: "shell_link_trailing_slash_dot", Entries: mergedUsr(File("usr/bin/dash", ELF(EMX8664, Loader)), Link("usr/bin/sh", "dash/."), loaderFile()), Want: []string{"shell_missing"}},
		{Name: "interp_trailing_slash", Entries: mergedUsr(File("usr/bin/sh", ELF(EMX8664, Loader+"/")), loaderFile()), Want: []string{"interp_missing"}},
		{Name: "dir_link_trailing_slash", Entries: []Entry{
			Link("bin", "usr/bin/"), Link("lib64", "usr/lib64/"), Dir("usr/bin"), Dir("usr/lib64"), shell(), loaderFile(),
		}},
	}
}
