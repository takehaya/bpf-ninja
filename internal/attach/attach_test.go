package attach

import (
	"strings"
	"testing"
)

func TestFindXDPProgramNoInterface(t *testing.T) {
	_, err := FindXDPProgram("nonexistent_iface_xyz")
	if err == nil {
		t.Fatal("expected error for nonexistent interface, got nil")
	}
}

func TestListFuncs(t *testing.T) {
	prog := loadTestXDP(t)
	funcs, err := ListFuncs(prog)
	if err != nil {
		t.Fatalf("ListFuncs: %v", err)
	}

	found := map[string]bool{}
	for _, f := range funcs {
		found[f.Name] = true
	}

	if !found["xdp_subfunc_test"] {
		t.Error("expected xdp_subfunc_test in function list")
	}
	if !found["process_packet"] {
		t.Error("expected process_packet in function list")
	}
}

func TestValidateSubfuncValid(t *testing.T) {
	prog := loadTestXDP(t)
	if err := ValidateSubfunc(prog, 0, "process_packet"); err != nil {
		t.Fatalf("ValidateSubfunc for valid func: %v", err)
	}
}

func TestValidateSubfuncNotFound(t *testing.T) {
	prog := loadTestXDP(t)
	err := ValidateSubfunc(prog, 0, "nonexistent_func")
	if err == nil {
		t.Fatal("expected error for nonexistent function, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
	if !strings.Contains(err.Error(), "process_packet") {
		t.Errorf("error should list available functions, got: %v", err)
	}
}
