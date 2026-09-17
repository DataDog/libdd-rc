package libddrcffi

import "sync"

// recordedDispatchResult is a dispatchResult call recorded by fakeConn, kept
// as its own type since fakeConn records the already-marshalled wire bytes
// rather than a handler's raw response and error.
type recordedDispatchResult struct {
	correlationID uint64
	encoded       []byte
}

// recordedDispatchError is a dispatchError call recorded by fakeConn
type recordedDispatchError struct {
	correlationID uint64
	errorCode     int
}

// fakeConn is a hand-written nativeConn test double, standing in for the
// real cgo-backed connection so Connection's own state machine and worker
// plumbing can be exercised without linking or driving the native library.
//
// Its methods are safe for concurrent use: Connection itself only calls them
// under its own lock or from one of invokePool's invoke workers, which can
// call dispatchResult concurrently with each other, but tests read the
// recorded calls from the goroutine driving the test.
type fakeConn struct {
	mu sync.Mutex

	connectedCalls    int
	recvCalls         [][]byte
	disconnectedCalls int
	dispatchResults   []recordedDispatchResult
	dispatchErrors    []recordedDispatchError
	freeCalls         int

	// recvErr, if set, is returned by every recv call instead of nil.
	recvErr error
}

func (f *fakeConn) connected() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connectedCalls++
}

func (f *fakeConn) recv(data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recvCalls = append(f.recvCalls, data)
	return f.recvErr
}

func (f *fakeConn) disconnected() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnectedCalls++
}

func (f *fakeConn) dispatchResult(correlationID uint64, encoded []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dispatchResults = append(f.dispatchResults, recordedDispatchResult{correlationID: correlationID, encoded: encoded})
}

func (f *fakeConn) dispatchError(correlationID uint64, errorCode int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dispatchErrors = append(f.dispatchErrors, recordedDispatchError{correlationID: correlationID, errorCode: errorCode})
}

func (f *fakeConn) free() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.freeCalls++
}
