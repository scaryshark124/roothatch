//go:build linux

package preflight

import (
	"errors"
	"fmt"
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
func Check(dir string) (Report, error) {
	rootfd, err := syscall.Open(dir, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Report{}, &RootError{Dir: dir, Err: err}
	}
	defer syscall.Close(rootfd)
	var r Report
	fd, st, ok := locate(rootfd, ShellPath, shellRole, &r)
	if !ok {
		return r, nil
	}
	data, size, err := readPinned(fd, st)
	syscall.Close(fd)
	if err != nil {
		r.add("read_error", ShellPath, "cannot read: "+err.Error())
		return r, nil
	}
	interp, has, prob := parseELF(data, size)
	if prob != nil {
		r.add(prob.code, ShellPath, prob.detail)
		return r, nil
	}
	if !has {
		r.Static = true
		return r, nil
	}
	r.Interp = clean(interp)
	if ifd, _, ok := locate(rootfd, interp, interpRole, &r); ok {
		syscall.Close(ifd)
	}
	return r, nil
}
