package admin

// lockState is the outcome of lockSocketPath.
type lockState int

const (
	lockHeld        lockState = iota // the lock was taken
	lockUnavailable                  // locking is not possible here; proceed unlocked
	lockContended                    // another process held it past the wait
)
