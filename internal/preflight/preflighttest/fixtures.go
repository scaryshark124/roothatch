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
	EMI386    = 3
	EMX8664   = 62
	EMAArch64 = 183
	// Loader is the x86-64 glibc PT_INTERP path.
	Loader = "/lib64/ld-linux-x86-64.so.2"
)

// ELF identification values used by Header.
const (
	ELFClass32 = 1
	ELFClass64 = 2
	ELFDataLSB = 1 // little-endian
	ELFDataMSB = 2 // big-endian
)

// Header returns a bare ELF file header with the given EI_CLASS, EI_DATA and
// e_machine, encoded in that class's own layout and byte order: 52 bytes for
// ELF32, 64 bytes for ELF64. It is ET_DYN, EV_CURRENT, with e_ehsize set and
// no program or section header tables.
func Header(class, data byte, machine uint16) []byte {
	var bo binary.ByteOrder = binary.LittleEndian
	if data == ELFDataMSB {
		bo = binary.BigEndian
	}
	size, ehsizeOff := 64, 52 // ELF64: e_entry, e_phoff and e_shoff are 8 bytes
	if class == ELFClass32 {
		size, ehsizeOff = 52, 40 // ELF32: e_entry, e_phoff and e_shoff are 4 bytes
	}
	b := make([]byte, size)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = class, data, 1 // EI_CLASS, EI_DATA, EI_VERSION
	bo.PutUint16(b[16:], 3)           // e_type ET_DYN
	bo.PutUint16(b[18:], machine)     // e_machine
	bo.PutUint32(b[20:], 1)           // e_version EV_CURRENT
	bo.PutUint16(b[ehsizeOff:], uint16(size))
	return b
}

// LoaderELF returns a synthetic healthy interpreter: a generated ELF64
// little-endian x86-64 image (never a host loader).
func LoaderELF() []byte { return ELF(EMX8664, "") }

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
	// Kernels is the expected sorted list of valid Debian-named kernel
	// versions found in /boot (Report.Kernels); nil means none.
	Kernels []string
	// Shortcuts names the optional root shortcut links (/vmlinuz,
	// /initrd.img) expected to be present, in check order.
	Shortcuts []string
	// Outside entries are created in the sandbox directory that contains
	// the root (as siblings of "root"); escaping links point at them. They
	// are synthetic sentinels that must never be read or changed.
	Outside []Entry
	// Findings, when non-nil, is the exact expected ordered list of
	// (code, path) pairs; its codes must equal Want.
	Findings []FindingPair
}

// FindingPair is an expected finding code and its sanitized in-root path.
type FindingPair struct{ Code, Path string }

// SandboxToken in a fixture link target is replaced by BuildFixture with the
// absolute sandbox path without its leading "/", so "/../../"+SandboxToken+
// "/x" names the outside sentinel x when resolved on the host.
const SandboxToken = "@SANDBOX@"

// BuildFixture creates fx beneath sandbox: Outside entries directly in
// sandbox, and Entries in sandbox/root, which it returns. sandbox must be an
// absolute path.
func BuildFixture(sandbox string, fx Fixture) (string, error) {
	if !filepath.IsAbs(sandbox) {
		return "", fmt.Errorf("sandbox %q is not absolute", sandbox)
	}
	if err := Build(sandbox, fx.Outside...); err != nil {
		return "", err
	}
	root := filepath.Join(sandbox, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		return "", err
	}
	tok := strings.TrimPrefix(filepath.ToSlash(sandbox), "/")
	entries := make([]Entry, len(fx.Entries))
	for i, e := range fx.Entries {
		if e.Kind == KindLink {
			e.Target = strings.ReplaceAll(e.Target, SandboxToken, tok)
		}
		entries[i] = e
	}
	return root, Build(root, entries...)
}

// KernelVersion is the version of the synthetic Debian boot layout.
const KernelVersion = "6.1.0-test"

// BootLayout returns a valid synthetic Debian /boot layout: a kernel and the
// matching initrd as plain placeholder bytes (never real kernel images).
func BootLayout() []Entry { return bootFilesAt("boot", KernelVersion) }

func bootFilesAt(dir, ver string) []Entry {
	return []Entry{
		File(dir+"/vmlinuz-"+ver, []byte("synthetic kernel placeholder "+ver)),
		File(dir+"/initrd.img-"+ver, []byte("synthetic initrd placeholder "+ver)),
	}
}

// withBoot adds the valid synthetic boot layout to every fixture so the
// boot checks pass and each fixture keeps exactly its shell/interpreter Want.
func withBoot(fxs []Fixture) []Fixture {
	for i := range fxs {
		fxs[i].Entries = append(append([]Entry{}, fxs[i].Entries...), BootLayout()...)
		fxs[i].Kernels = []string{KernelVersion}
	}
	return fxs
}

func mergedUsr(extra ...Entry) []Entry {
	return append([]Entry{
		Link("bin", "usr/bin"), Link("lib", "usr/lib"), Link("lib64", "usr/lib64"),
		Dir("usr/bin"), Dir("usr/lib"), Dir("usr/lib64"),
	}, extra...)
}

func loaderFile() Entry {
	return File("usr/lib64/ld-linux-x86-64.so.2", LoaderELF())
}

func shell() Entry { return File("usr/bin/sh", ELF(EMX8664, Loader)) }

// sentinel is a distinctive synthetic outside-root file named name.
func sentinel(name string) Entry {
	return File(name, []byte("synthetic outside-root sentinel "+name+"; must never be read\n"))
}

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
	return append(withBoot([]Fixture{
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
		{Name: "debian_absolute_loader", Entries: debian(File("usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", LoaderELF()))},
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
	}), append(append(bootCatalog(), InterpCatalog()...), InterpTypeCatalog()...)...)
}

// LargeLoaderSize is the size of the interp_large_valid_header loader, well
// beyond the 64 KiB read cap.
const LargeLoaderSize = 1 << 20

// InterpCatalog returns the interpreter header fixtures (also included in
// Catalog): a healthy /bin/sh whose PT_INTERP resolves inside the root to a
// regular file with the given contents, plus the valid boot layout, so only
// interpreter header findings are expected, reported at the PT_INTERP path.
func InterpCatalog() []Fixture {
	const ld = "usr/lib64/ld-linux-x86-64.so.2"
	with := func(loader []byte) []Entry { return mergedUsr(shell(), File(ld, loader)) }
	bad := func(name, code string, loader []byte) Fixture {
		return Fixture{Name: name, Entries: with(loader), Want: []string{code},
			Findings: []FindingPair{{code, Loader}}}
	}
	ident := func(i int, v byte) []byte {
		b := Header(ELFClass64, ELFDataLSB, EMX8664)
		b[i] = v
		return b
	}
	large := make([]byte, LargeLoaderSize)
	copy(large, Header(ELFClass64, ELFDataLSB, EMX8664))
	const real = "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
	return withBoot([]Fixture{
		bad("interp_elf_text", "interp_elf_invalid", []byte("synthetic loader placeholder")),
		bad("interp_elf_empty", "interp_elf_invalid", nil),
		bad("interp_elf_truncated_elf64", "interp_elf_invalid", Header(ELFClass64, ELFDataLSB, EMX8664)[:63]),
		bad("interp_elf_bad_class", "interp_elf_invalid", ident(4, 3)),
		bad("interp_elf_bad_data", "interp_elf_invalid", ident(5, 3)),
		bad("interp_elf_bad_ident_version", "interp_elf_invalid", ident(6, 2)),
		bad("interp_elf_truncated_elf32", "interp_elf_invalid", Header(ELFClass32, ELFDataLSB, EMI386)[:51]),
		bad("interp_arch_aarch64", "interp_arch_unsupported", Header(ELFClass64, ELFDataLSB, EMAArch64)),
		bad("interp_arch_elf32_i386", "interp_arch_unsupported", Header(ELFClass32, ELFDataLSB, EMI386)),
		bad("interp_arch_elf64_big_endian", "interp_arch_unsupported", Header(ELFClass64, ELFDataMSB, EMX8664)),
		{Name: "interp_link_relative_in_tree", Entries: mergedUsr(shell(), File(real, LoaderELF()),
			Link(ld, "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"))},
		{Name: "interp_link_absolute_in_tree", Entries: mergedUsr(shell(), File(real, LoaderELF()),
			Link(ld, "/"+real))},
		{Name: "interp_large_valid_header", Entries: with(large)},
	})
}

// bootCatalog returns the /boot and shortcut-link fixtures. Each has a
// healthy shell and interpreter unless stated otherwise, so only boot
// findings are expected.
func bootCatalog() []Fixture {
	v := KernelVersion
	healthy := func(extra ...Entry) []Entry { return mergedUsr(append([]Entry{shell(), loaderFile()}, extra...)...) }
	layout := func(extra ...Entry) []Entry { return healthy(append(BootLayout(), extra...)...) }
	one := []string{v}
	both := []string{"/vmlinuz", "/initrd.img"}
	return []Fixture{
		{Name: "boot_shortcuts_relative", Entries: layout(Link("vmlinuz", "boot/vmlinuz-"+v), Link("initrd.img", "boot/initrd.img-"+v)),
			Kernels: one, Shortcuts: both},
		{Name: "boot_shortcuts_absolute", Entries: layout(Link("vmlinuz", "/boot/vmlinuz-"+v), Link("initrd.img", "/boot/initrd.img-"+v)),
			Kernels: one, Shortcuts: both},
		{Name: "boot_shortcut_regular_file", Entries: layout(File("vmlinuz", []byte("k"))), Kernels: one, Shortcuts: []string{"/vmlinuz"}},
		{Name: "boot_missing", Entries: healthy(), Want: []string{"kernel_missing"}},
		{Name: "boot_not_directory", Entries: healthy(File("boot", []byte("not a dir"))), Want: []string{"kernel_missing"}},
		{Name: "boot_empty", Entries: healthy(Dir("boot")), Want: []string{"kernel_missing"}},
		{Name: "boot_kernel_empty_version", Entries: healthy(File("boot/vmlinuz-", []byte("k")), File("boot/initrd.img-", []byte("i"))),
			Want: []string{"kernel_missing"}},
		{Name: "boot_kernel_without_initrd", Entries: healthy(File("boot/vmlinuz-"+v, []byte("k"))),
			Want: []string{"initrd_missing"}, Kernels: one},
		{Name: "boot_two_kernels_one_initrd", Entries: layout(File("boot/vmlinuz-6.2.0-test", []byte("k"))),
			Want: []string{"initrd_missing"}, Kernels: []string{v, "6.2.0-test"}},
		{Name: "boot_two_kernels_two_initrds", Entries: layout(bootFilesAt("boot", "5.10.0-test")...),
			Kernels: []string{"5.10.0-test", v}},
		{Name: "boot_initrd_directory", Entries: healthy(File("boot/vmlinuz-"+v, []byte("k")), Dir("boot/initrd.img-"+v)),
			Want: []string{"initrd_missing"}, Kernels: one},
		// An escaping initrd is reported as symlink_escape, never followed,
		// and still reported as initrd_missing; the kernel stays counted.
		{Name: "boot_initrd_escape", Entries: healthy(File("boot/vmlinuz-"+v, []byte("k")), Link("boot/initrd.img-"+v, "../../outside-initrd")),
			Outside:  []Entry{sentinel("outside-initrd")},
			Want:     []string{"symlink_escape", "initrd_missing"},
			Findings: []FindingPair{{"symlink_escape", "/boot/initrd.img-" + v}, {"initrd_missing", "/boot/initrd.img-" + v}},
			Kernels:  one},
		{Name: "boot_initrd_escape_with_valid_pair", Entries: layout(File("boot/vmlinuz-6.9.0-esc", []byte("k")),
			Link("boot/initrd.img-6.9.0-esc", "../../sentinel-initrd")),
			Outside:  []Entry{sentinel("sentinel-initrd")},
			Want:     []string{"symlink_escape", "initrd_missing"},
			Findings: []FindingPair{{"symlink_escape", "/boot/initrd.img-6.9.0-esc"}, {"initrd_missing", "/boot/initrd.img-6.9.0-esc"}},
			Kernels:  []string{v, "6.9.0-esc"}},
		// Created relative-then-absolute; sorted enumeration reports 7.0 first.
		{Name: "boot_two_initrd_escapes", Entries: healthy(
			File("boot/vmlinuz-9.0-rel", []byte("k")), Link("boot/initrd.img-9.0-rel", "../../x"),
			File("boot/vmlinuz-7.0-abs", []byte("k")), Link("boot/initrd.img-7.0-abs", "/../../"+SandboxToken+"/y")),
			Outside: []Entry{sentinel("x"), sentinel("y")},
			Want:    []string{"symlink_escape", "initrd_missing", "symlink_escape", "initrd_missing"},
			Findings: []FindingPair{
				{"symlink_escape", "/boot/initrd.img-7.0-abs"}, {"initrd_missing", "/boot/initrd.img-7.0-abs"},
				{"symlink_escape", "/boot/initrd.img-9.0-rel"}, {"initrd_missing", "/boot/initrd.img-9.0-rel"}},
			Kernels: []string{"7.0-abs", "9.0-rel"}},
		{Name: "boot_initrd_link_in_tree_relative", Entries: healthy(File("boot/vmlinuz-"+v, []byte("k")),
			File("opt/i/initrd-image", []byte("i")), Link("boot/initrd.img-"+v, "../opt/i/initrd-image")), Kernels: one},
		{Name: "boot_initrd_link_in_tree", Entries: healthy(File("boot/vmlinuz-"+v, []byte("k")),
			File("opt/i/initrd", []byte("i")), Link("boot/initrd.img-"+v, "/opt/i/initrd")), Kernels: one},
		{Name: "boot_kernel_directory", Entries: healthy(Dir("boot/vmlinuz-"+v), File("boot/initrd.img-"+v, []byte("i"))),
			Want: []string{"kernel_missing"}},
		{Name: "boot_kernel_fifo", Entries: healthy(FIFO("boot/vmlinuz-"+v), File("boot/initrd.img-"+v, []byte("i"))),
			Want: []string{"kernel_missing"}},
		{Name: "boot_kernel_escape", Entries: healthy(Link("boot/vmlinuz-"+v, "../../outside-kernel"), File("boot/initrd.img-"+v, []byte("i"))),
			Outside:  []Entry{sentinel("outside-kernel")},
			Want:     []string{"symlink_escape", "kernel_missing"},
			Findings: []FindingPair{{"symlink_escape", "/boot/vmlinuz-" + v}, {"kernel_missing", "/boot"}}},
		{Name: "boot_kernel_link_in_tree", Entries: healthy(File("opt/k/vmlinuz", []byte("k")), Link("boot/vmlinuz-"+v, "/opt/k/vmlinuz"),
			File("boot/initrd.img-"+v, []byte("i"))), Kernels: one},
		// Escaping kernel candidates are reported, never followed and never
		// counted; a valid pair still satisfies the kernel check.
		{Name: "boot_kernel_escape_with_valid_pair", Entries: layout(Link("boot/vmlinuz-6.9.0-esc", "../../sentinel")),
			Outside: []Entry{sentinel("sentinel")}, Want: []string{"symlink_escape"},
			Findings: []FindingPair{{"symlink_escape", "/boot/vmlinuz-6.9.0-esc"}}, Kernels: one},
		// Created relative-then-absolute; sorted enumeration reports 7.0 first.
		{Name: "boot_two_kernel_escapes_with_valid_pair", Entries: layout(
			Link("boot/vmlinuz-9.0-rel", "../../sentinel-rel"),
			Link("boot/vmlinuz-7.0-abs", "/../../"+SandboxToken+"/sentinel-abs")),
			Outside:  []Entry{sentinel("sentinel-rel"), sentinel("sentinel-abs")},
			Want:     []string{"symlink_escape", "symlink_escape"},
			Findings: []FindingPair{{"symlink_escape", "/boot/vmlinuz-7.0-abs"}, {"symlink_escape", "/boot/vmlinuz-9.0-rel"}},
			Kernels:  one},
		{Name: "boot_kernel_link_in_tree_relative", Entries: healthy(File("opt/k/kernel-image", []byte("k")),
			Link("boot/vmlinuz-"+v, "../opt/k/kernel-image"), File("boot/initrd.img-"+v, []byte("i"))), Kernels: one},
		{Name: "boot_vmlinuz_dangling", Entries: layout(Link("vmlinuz", "boot/vmlinuz-9.9.9-absent")),
			Want: []string{"boot_link_broken"}, Kernels: one, Shortcuts: []string{"/vmlinuz"}},
		{Name: "boot_vmlinuz_escape", Entries: layout(Link("vmlinuz", "../boot/vmlinuz-"+v)),
			Want: []string{"symlink_escape"}, Kernels: one, Shortcuts: []string{"/vmlinuz"}},
		{Name: "boot_vmlinuz_loop", Entries: layout(Link("vmlinuz", "vmlinuz")),
			Want: []string{"boot_link_broken"}, Kernels: one, Shortcuts: []string{"/vmlinuz"}},
		{Name: "boot_vmlinuz_directory", Entries: layout(Link("vmlinuz", "boot")),
			Want: []string{"boot_link_broken"}, Kernels: one, Shortcuts: []string{"/vmlinuz"}},
		{Name: "boot_initrd_link_trailing_slash", Entries: layout(Link("initrd.img", "boot/initrd.img-"+v+"/")),
			Want: []string{"boot_link_broken"}, Kernels: one, Shortcuts: []string{"/initrd.img"}},
		{Name: "boot_symlink_escape", Entries: healthy(Link("boot", "../outside-boot")), Want: []string{"symlink_escape"}},
		// Real directories are created before the boot link that names them.
		{Name: "boot_symlink_in_tree", Entries: healthy(append(bootFilesAt("realboot", v), Link("boot", "realboot"))...), Kernels: one},
		{Name: "boot_symlink_absolute_in_tree", Entries: healthy(append(bootFilesAt("srv/realboot", v), Link("boot", "/srv/realboot/"))...),
			Kernels: one},
		{Name: "boot_and_shell_findings", Entries: mergedUsr(loaderFile(), Dir("boot"), Link("vmlinuz", "nowhere")),
			Want: []string{"shell_missing", "kernel_missing", "boot_link_broken"}, Shortcuts: []string{"/vmlinuz"}},
	}
}
