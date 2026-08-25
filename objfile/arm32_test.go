package objfile

import "testing"

func TestArmPool(t *testing.T) {
	code := []byte{
		0x00, 0x00, 0x9f, 0xe5, // LDR R0, [PC] -> pool at +8
		0x1e, 0xff, 0x2f, 0xe1, // BX LR
		0x40, 0x12, 0x0b, 0x00, // pool word 0xb1240
	}
	pool := armPool(code)
	if len(pool) != 1 || !pool[8] {
		t.Fatalf("pool = %v, want {8}", pool)
	}
}
