package edge

import "testing"

func TestSemaphore(t *testing.T) {
	var unlimited *semaphore
	if !unlimited.tryAcquire() {
		t.Fatal("nil semaphore must always acquire")
	}
	unlimited.release() // must not panic

	s := newSemaphore(1)
	if !s.tryAcquire() {
		t.Fatal("first acquire should succeed")
	}
	if s.tryAcquire() {
		t.Fatal("second acquire should fail at cap 1")
	}
	s.release()
	if !s.tryAcquire() {
		t.Fatal("acquire after release should succeed")
	}
}
