package preflight

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbidden names privileged, namespace, process-execution and mutation
// operations that the read-only preflight and CLI code must never reference.
var forbiddenSelectors = map[string]map[string]bool{
	"syscall": set("Mount", "Unmount", "Chroot", "PivotRoot", "Unshare", "Setns", "Exec", "ForkExec",
		"StartProcess", "Clone", "SYS_MOUNT", "SYS_UMOUNT2", "SYS_CHROOT", "SYS_PIVOT_ROOT",
		"SYS_UNSHARE", "SYS_SETNS", "SYS_CLONE", "SYS_CLONE3", "SYS_EXECVE", "SYS_EXECVEAT",
		"SYS_FORK", "SYS_VFORK", "CLONE_NEWNS", "CLONE_NEWUSER", "CLONE_NEWPID", "CLONE_NEWNET"),
	"golang.org/x/sys/unix": set("Mount", "Unmount", "Chroot", "PivotRoot", "Unshare", "Setns", "Exec",
		"MoveMount", "Fsmount", "Fsopen"),
	"os": set("StartProcess"),
}

// mutating names are additionally forbidden in production read-only code.
var mutatingSelectors = map[string]map[string]bool{
	"syscall": set("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "Unlink", "Unlinkat",
		"Rmdir", "Rename", "Renameat", "Mkdir", "Mkdirat", "Mknod", "Mknodat", "Mkfifo", "Symlink",
		"Link", "Chmod", "Fchmod", "Fchmodat", "Chown", "Fchown", "Fchownat", "Lchown", "Truncate",
		"Ftruncate", "Write", "Pwrite", "Utimes", "UtimesNano", "Creat"),
	"os": set("Create", "OpenFile", "WriteFile", "Remove", "RemoveAll", "Rename", "Mkdir", "MkdirAll",
		"MkdirTemp", "CreateTemp", "Chmod", "Chown", "Lchown", "Chtimes", "Symlink", "Link", "Truncate"),
}

var rawSyscalls = set("Syscall", "Syscall6", "RawSyscall", "RawSyscall6")

func set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

// scanSource reports forbidden imports and selectors in one Go source file.
// readOnly additionally rejects mutating operations.
func scanSource(name, src string, readOnly bool) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{"parse: " + err.Error()}
	}
	var bad []string
	alias := map[string]string{}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if path == "os/exec" || path == "plugin" {
			bad = append(bad, "import "+path)
		}
		local := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			local = imp.Name.Name
		}
		alias[local] = path
	}
	sel := func(e ast.Expr) (string, string, bool) {
		s, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", "", false
		}
		id, ok := s.X.(*ast.Ident)
		if !ok {
			return "", "", false
		}
		path, ok := alias[id.Name]
		return path, s.Sel.Name, ok
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			path, name, ok := sel(n)
			if !ok {
				return true
			}
			if forbiddenSelectors[path][name] || (readOnly && mutatingSelectors[path][name]) {
				bad = append(bad, fset.Position(n.Pos()).String()+": "+path+"."+name)
			}
		case *ast.CallExpr:
			path, name, ok := sel(n.Fun)
			if !ok || (path != "syscall" && path != "golang.org/x/sys/unix") || !rawSyscalls[name] {
				return true
			}
			// Raw syscalls are allowed only for read-only readlinkat.
			if len(n.Args) == 0 {
				bad = append(bad, "raw syscall without trap")
				return true
			}
			if p, trap, ok := sel(n.Args[0]); !ok || p != path || trap != "SYS_READLINKAT" {
				bad = append(bad, fset.Position(n.Pos()).String()+": raw syscall other than SYS_READLINKAT")
			}
		}
		return true
	})
	return bad
}

func TestScannerDetectsForbiddenUse(t *testing.T) {
	cases := map[string]string{
		"exec import":    `package p; import x "os/exec"; var _ = x.Command`,
		"mount":          `package p; import "syscall"; func f() { syscall.Mount("", "", "", 0, "") }`,
		"aliased chroot": `package p; import s "syscall"; func f() { s.Chroot("/") }`,
		"unix unshare":   `package p; import "golang.org/x/sys/unix"; func f() { unix.Unshare(0) }`,
		"raw mount":      `package p; import "syscall"; func f() { syscall.Syscall(syscall.SYS_MOUNT, 0, 0, 0) }`,
		"raw literal":    `package p; import "syscall"; func f() { syscall.Syscall6(165, 0, 0, 0, 0, 0, 0) }`,
		"write open":     `package p; import "syscall"; var _ = syscall.O_RDWR`,
		"os remove":      `package p; import "os"; func f() { os.Remove("x") }`,
	}
	for name, src := range cases {
		if len(scanSource(name+".go", src, true)) == 0 {
			t.Errorf("%s: scanner missed forbidden use", name)
		}
	}
	ok := `package p; import "syscall"; func f() { syscall.Syscall6(syscall.SYS_READLINKAT, 0, 0, 0, 0, 0, 0) }`
	if bad := scanSource("ok.go", ok, true); len(bad) != 0 {
		t.Errorf("scanner rejected readlinkat: %v", bad)
	}
}

// TestNoExecMountOrMutation fails if production preflight, CLI or command
// code imports os/exec, uses mount/chroot/namespace/exec operations, or (for
// read-only packages) any filesystem mutation.
func TestNoExecMountOrMutation(t *testing.T) {
	dirs := map[string]bool{ // directory -> read-only production code
		".":                   true,
		"../cli":              true,
		"../../cmd/roothatch": true,
		"preflighttest":       false, // test fixture builder writes temp trees
	}
	scanned := 0
	for dir, readOnly := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			isTest := strings.HasSuffix(file, "_test.go")
			if isTest && readOnly {
				continue // tests build fixtures; production code is what runs on targets
			}
			src, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			scanned++
			if bad := scanSource(file, string(src), readOnly); len(bad) != 0 {
				t.Errorf("%s: forbidden use: %v", file, bad)
			}
		}
	}
	if scanned < 4 {
		t.Fatalf("scanned only %d files; scan scope is wrong", scanned)
	}
}
