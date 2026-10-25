//go:build linux

package preflight

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	oPath      = 0x200000 // O_PATH (linux); not exported by package syscall
	maxHops    = 40       // total symlinks followed per resolution, like Linux
	maxLinkLen = 4096
)

type failKind int

const (
	failMissing failKind = iota
	failEscape
	failLoop
	failIO
)

type resolveFail struct {
	kind   failKind
	detail string
}

type frame struct {
	fd   int
	name string
}

func displayPath(stack []frame, last string) string {
	var b strings.Builder
	for _, f := range stack[1:] {
		b.WriteString("/" + f.name)
	}
	if last != "" {
		b.WriteString("/" + last)
	}
	if b.Len() == 0 {
		return "/"
	}
	return b.String()
}

func dupCloexec(fd int) (int, error) {
	n, err := syscall.Dup(fd)
	if err == nil {
		syscall.CloseOnExec(n)
	}
	return n, err
}

// readlinkFD reads the target of the symlink pinned by an O_PATH descriptor
// (readlinkat with an empty path), so a rename cannot substitute another link.
func readlinkFD(fd int) (string, error) {
	buf := make([]byte, maxLinkLen)
	empty := []byte{0}
	n, _, e := syscall.Syscall6(syscall.SYS_READLINKAT, uintptr(fd),
		uintptr(unsafe.Pointer(&empty[0])), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if e != 0 {
		return "", e
	}
	if int(n) >= len(buf) {
		return "", errors.New("symlink target too long")
	}
	return string(buf[:n]), nil
}

// resolve walks p component by component beneath rootfd using only
// O_PATH|O_NOFOLLOW openat calls on pinned directory descriptors. Absolute
// symlink targets restart at rootfd; ".." pops the physical directory stack
// and fails closed at the root. It returns an O_PATH descriptor for the final
// object and its in-root path.
func resolve(rootfd int, p string) (int, string, *resolveFail) {
	first, err := dupCloexec(rootfd)
	if err != nil {
		return -1, "", &resolveFail{failIO, "cannot duplicate root descriptor: " + err.Error()}
	}
	stack := []frame{{fd: first}}
	defer func() {
		for _, f := range stack {
			syscall.Close(f.fd)
		}
	}()
	popTo := func(n int) {
		for len(stack) > n {
			syscall.Close(stack[len(stack)-1].fd)
			stack = stack[:len(stack)-1]
		}
	}
	pending := strings.Split(p, "/")
	hops := 0
	lastLink := ""
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(stack) == 1 {
				if lastLink != "" {
					return -1, "", &resolveFail{failEscape, "symlink " + lastLink + " leads outside the root; not followed"}
				}
				return -1, "", &resolveFail{failEscape, "path climbs above the root; not followed"}
			}
			popTo(len(stack) - 1)
			continue
		}
		cur := displayPath(stack, c)
		fd, err := syscall.Openat(stack[len(stack)-1].fd, c, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			if err == syscall.ENOENT || err == syscall.ENOTDIR {
				return -1, "", &resolveFail{failMissing, clean(cur) + " does not exist inside the root"}
			}
			return -1, "", &resolveFail{failIO, "cannot look up " + clean(cur) + ": " + err.Error()}
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			syscall.Close(fd)
			return -1, "", &resolveFail{failIO, "cannot stat " + clean(cur) + ": " + err.Error()}
		}
		switch st.Mode & syscall.S_IFMT {
		case syscall.S_IFLNK:
			target, err := readlinkFD(fd)
			syscall.Close(fd)
			if err != nil {
				return -1, "", &resolveFail{failIO, "cannot read symlink " + clean(cur) + ": " + err.Error()}
			}
			if hops++; hops > maxHops {
				return -1, "", &resolveFail{failLoop, fmt.Sprintf("more than %d symlinks while resolving (loop at %s)", maxHops, clean(cur))}
			}
			lastLink = clean(cur) + " -> " + strconv.Quote(target)
			if strings.HasPrefix(target, "/") {
				popTo(1) // absolute targets are re-rooted at the selected root
			}
			pending = append(strings.Split(target, "/"), pending...)
		case syscall.S_IFDIR:
			stack = append(stack, frame{fd: fd, name: c})
		default:
			// Any remaining component, including "" or "." from a trailing
			// slash, needs a directory here; the kernel reports ENOTDIR.
			if len(pending) > 0 {
				syscall.Close(fd)
				return -1, "", &resolveFail{failMissing, clean(cur) + " is not a directory, so " + strconv.Quote(p) + " does not exist inside the root"}
			}
			return fd, cur, nil
		}
	}
	fd, err := dupCloexec(stack[len(stack)-1].fd)
	if err != nil {
		return -1, "", &resolveFail{failIO, "cannot duplicate descriptor: " + err.Error()}
	}
	return fd, displayPath(stack, ""), nil
}

func kindName(mode uint32) string {
	switch mode & syscall.S_IFMT {
	case syscall.S_IFDIR:
		return "a directory"
	case syscall.S_IFIFO:
		return "a FIFO"
	case syscall.S_IFCHR:
		return "a character device"
	case syscall.S_IFBLK:
		return "a block device"
	case syscall.S_IFSOCK:
		return "a socket"
	}
	return "not a regular file"
}

// readPinned reads at most elfPrefix bytes from the regular file pinned by an
// O_PATH descriptor. It reopens exactly that object through /proc/self/fd and
// verifies device, inode and type, so no other pathname is ever opened.
func readPinned(pinned int, want *syscall.Stat_t) ([]byte, int64, error) {
	fd, err := syscall.Open("/proc/self/fd/"+strconv.Itoa(pinned),
		syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("cannot reopen pinned file via /proc/self/fd: %v", err)
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, 0, err
	}
	if st.Dev != want.Dev || st.Ino != want.Ino || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, 0, errors.New("reopened file is not the pinned regular file")
	}
	buf := make([]byte, elfPrefix)
	n := 0
	for n < len(buf) {
		m, err := syscall.Pread(fd, buf[n:], int64(n))
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		if m == 0 {
			break
		}
		n += m
	}
	return buf[:n], st.Size, nil
}

type role struct{ missing, notRegular string }

var (
	shellRole  = role{"shell_missing", "shell_not_regular"}
	interpRole = role{"interp_missing", "interp_not_regular"}
)

// locate resolves p and requires a regular file, recording findings in r.
func locate(rootfd int, p string, ro role, r *Report) (int, *syscall.Stat_t, bool) {
	fd, cur, fail := resolve(rootfd, p)
	if fail != nil {
		code := map[failKind]string{failMissing: ro.missing, failEscape: "symlink_escape",
			failLoop: "symlink_loop", failIO: "read_error"}[fail.kind]
		r.add(code, p, fail.detail)
		return -1, nil, false
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		r.add("read_error", p, "cannot stat "+clean(cur)+": "+err.Error())
		return -1, nil, false
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		syscall.Close(fd)
		r.add(ro.notRegular, p, "resolves to "+clean(cur)+", which is "+kindName(st.Mode)+"; not opened")
		return -1, nil, false
	}
	return fd, &st, true
}

// Check inspects the root tree at dir. It returns an error only when dir
// itself cannot be opened as a directory; every other problem is a finding.
// The shell/interpreter checks and the /boot checks run independently and
// all findings are reported in a deterministic order.
func Check(dir string) (Report, error) {
	return run(dir, allPhases())
}

// CheckShell inspects the root tree at dir with only the /bin/sh and ELF
// interpreter phase of Check, admitting dir exactly as Check does. It never
// calls the independent /boot or shortcut-link phases, although /bin/sh or
// its PT_INTERP may themselves resolve beneath /boot.
func CheckShell(dir string) (Report, error) {
	return run(dir, shellPhases())
}

// phase is one independent check run against an admitted root descriptor.
type phase func(rootfd int, r *Report)

// allPhases is the full Check selection, in report order.
func allPhases() []phase { return []phase{checkShell, checkBoot, checkShortcuts} }

// shellPhases is the CheckShell selection: the shell/interpreter phase only.
func shellPhases() []phase { return []phase{checkShell} }

// run admits dir as the root, runs exactly the selected phases in order on
// that one descriptor, and closes it.
func run(dir string, phases []phase) (Report, error) {
	rootfd, err := syscall.Open(dir, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Report{}, &RootError{Dir: dir, Err: err}
	}
	defer syscall.Close(rootfd)
	var r Report
	for _, p := range phases {
		p(rootfd, &r)
	}
	return r, nil
}

func checkShell(rootfd int, r *Report) {
	fd, st, ok := locate(rootfd, ShellPath, shellRole, r)
	if !ok {
		return
	}
	data, size, err := readPinned(fd, st)
	syscall.Close(fd)
	if err != nil {
		r.add("read_error", ShellPath, "cannot read: "+err.Error())
		return
	}
	interp, has, prob := parseELF(data, size)
	if prob != nil {
		r.add(prob.code, ShellPath, prob.detail)
		return
	}
	// Mode bits of the resolved regular shell, from the Fstat locate already
	// made; not an effective-access check. Later checks still run.
	if st.Mode&0o111 == 0 {
		r.add("shell_not_executable", ShellPath, fmt.Sprintf("resolves to a regular file with mode %04o; "+
			"no owner, group or other execute bit is set (mode bits only; not a check of whether any user can run it)",
			st.Mode&0o7777))
	}
	if !has {
		r.Static = true
		return
	}
	r.Interp = clean(interp)
	if ifd, ist, ok := locate(rootfd, interp, interpRole, r); ok {
		// Read the interpreter through the descriptor locate pinned; it is
		// closed before either result is handled.
		data, _, err := readPinned(ifd, ist)
		syscall.Close(ifd)
		if err != nil {
			r.add("read_error", interp, "cannot read: "+err.Error())
			return
		}
		if prob := interpHeader(data); prob != nil {
			r.add(prob.code, interp, prob.detail)
		} else if ist.Mode&0o111 == 0 {
			// Mode bits of the resolved regular interpreter, from the Fstat
			// locate already made (ist, not the shell's st); not an
			// effective-access check.
			r.add("interp_not_executable", interp, fmt.Sprintf("resolves to a regular file with mode %04o; "+
				"no owner, group or other execute bit is set (mode bits only; not a check of whether any user can run it)",
				ist.Mode&0o7777))
		}
	}
}

// regularIn resolves p confined to the root and reports whether it is a
// regular file. On failure it returns the resolver failure, or a failMissing
// failure describing the non-regular object. It never opens file contents.
func regularIn(rootfd int, p string) (string, *resolveFail) {
	fd, cur, fail := resolve(rootfd, p)
	if fail != nil {
		return "", fail
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return "", &resolveFail{failIO, "cannot stat " + clean(cur) + ": " + err.Error()}
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return "", &resolveFail{failMissing, "resolves to " + clean(cur) + ", which is " + kindName(st.Mode)}
	}
	return cur, nil
}

// listPinnedDir lists the names in the directory pinned by an O_PATH
// descriptor. It reopens exactly that directory relative to the pinned
// descriptor (".", O_NOFOLLOW) and verifies device and inode, so no pathname
// from the selected root is walked again. It enforces maxBootEntries and
// maxBootName.
func listPinnedDir(pinned int) ([]string, error) {
	var want syscall.Stat_t
	if err := syscall.Fstat(pinned, &want); err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(pinned, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open directory for listing: %v", err)
	}
	f := os.NewFile(uintptr(fd), "boot")
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Dev != want.Dev || st.Ino != want.Ino || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return nil, errors.New("reopened directory is not the pinned directory")
	}
	var names []string
	for {
		batch, err := f.Readdirnames(256)
		for _, n := range batch {
			if len(n) == 0 || len(n) > maxBootName {
				return nil, fmt.Errorf("entry name length %d outside 1..%d", len(n), maxBootName)
			}
		}
		names = append(names, batch...)
		if len(names) > maxBootEntries {
			return nil, fmt.Errorf("more than %d entries; not enumerated further", maxBootEntries)
		}
		if err == io.EOF || (err == nil && len(batch) == 0) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("cannot list directory: %v", err)
		}
	}
	sort.Strings(names)
	return names, nil
}

const (
	kernelPrefix = "vmlinuz-"
	initrdPrefix = "initrd.img-"
	debianNote   = " (Debian naming convention consistency check; not a bootability verdict)"
)

// checkBoot checks in-tree /boot for Debian-named kernels and matching
// initrds. It never reads kernel or initrd contents.
func checkBoot(rootfd int, r *Report) {
	bootfd, cur, fail := resolve(rootfd, BootDir)
	if fail != nil {
		switch fail.kind {
		case failEscape:
			r.add("symlink_escape", BootDir, fail.detail)
		case failIO:
			r.add("read_error", BootDir, fail.detail)
		case failLoop:
			r.add("kernel_missing", BootDir, fail.detail+"; no vmlinuz-<version> kernel in /boot"+debianNote)
		default:
			r.add("kernel_missing", BootDir, "/boot does not exist inside the root; no vmlinuz-<version> kernel"+debianNote)
		}
		return
	}
	var st syscall.Stat_t
	err := syscall.Fstat(bootfd, &st)
	if err != nil {
		syscall.Close(bootfd)
		r.add("read_error", BootDir, "cannot stat "+clean(cur)+": "+err.Error())
		return
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		syscall.Close(bootfd)
		r.add("kernel_missing", BootDir, "/boot resolves to "+clean(cur)+", which is "+kindName(st.Mode)+
			", not a directory; no vmlinuz-<version> kernel"+debianNote)
		return
	}
	names, err := listPinnedDir(bootfd)
	syscall.Close(bootfd)
	if err != nil {
		r.add("read_error", BootDir, "cannot enumerate "+clean(cur)+": "+err.Error())
		return
	}
	// Resolve candidates by in-root path from the root so ".." and absolute
	// targets are handled by the confined resolver.
	var kernels []string
	skipped := 0
	for _, n := range names {
		ver, ok := strings.CutPrefix(n, kernelPrefix)
		if !ok {
			continue
		}
		if ver == "" {
			skipped++
			continue
		}
		if _, f := regularIn(rootfd, BootDir+"/"+n); f != nil {
			switch f.kind {
			case failIO:
				r.add("read_error", BootDir+"/"+n, f.detail)
			case failEscape:
				// Reported at the in-root candidate; never followed or counted.
				r.add("symlink_escape", BootDir+"/"+n, f.detail)
			}
			skipped++
			continue
		}
		kernels = append(kernels, ver)
	}
	if len(kernels) == 0 {
		detail := "no vmlinuz-<version> kernel in /boot" + debianNote
		if skipped > 0 {
			detail += fmt.Sprintf("; %d vmlinuz-* entr(y/ies) ignored (empty version or not a regular file inside the root)", skipped)
		}
		r.add("kernel_missing", BootDir, detail)
		return
	}
	for _, ver := range kernels {
		r.Kernels = append(r.Kernels, clean(ver))
		ip := BootDir + "/" + initrdPrefix + ver
		if _, f := regularIn(rootfd, ip); f != nil {
			if f.kind == failEscape {
				// Reported at the in-root initrd path; never followed.
				r.add("symlink_escape", ip, f.detail)
			}
			r.add("initrd_missing", ip, "kernel version "+clean(ver)+" has no matching initrd.img-"+clean(ver)+
				" regular file inside the root: "+f.detail+debianNote)
		}
	}
}

// checkShortcuts checks the optional root shortcut links /vmlinuz and
// /initrd.img. An absent entry is not a finding.
func checkShortcuts(rootfd int, r *Report) {
	for _, p := range ShortcutLinks {
		ls := LinkStatus{Path: p}
		probe, err := syscall.Openat(rootfd, strings.TrimPrefix(p, "/"), oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err == syscall.ENOENT {
			r.Links = append(r.Links, ls)
			continue
		}
		if err != nil {
			r.Links = append(r.Links, ls)
			r.add("read_error", p, "cannot look up "+p+": "+err.Error())
			continue
		}
		syscall.Close(probe)
		ls.Present = true
		cur, f := regularIn(rootfd, p)
		switch {
		case f == nil:
			ls.OK, ls.Resolved = true, clean(cur)
		case f.kind == failEscape:
			r.add("symlink_escape", p, f.detail)
		case f.kind == failIO:
			r.add("read_error", p, f.detail)
		default:
			r.add("boot_link_broken", p, "optional shortcut does not resolve to a regular file inside the root: "+f.detail+debianNote)
		}
		r.Links = append(r.Links, ls)
	}
}
