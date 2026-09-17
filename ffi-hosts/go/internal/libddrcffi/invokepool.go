package libddrcffi

import (
	"fmt"
	"sync"

	magictunnelv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel"
)

const (
	dispatchQueueCap = 100

	// invokeWorkerCount is the size of the goroutine pool that invokes
	// handlers concurrently.
	invokeWorkerCount = 8
)

// dispatchJob is a single DispatchCb invocation, already decoded and routed
// to a handler by goDispatchCb, queued for processing by the invoke worker
// goroutine.
type dispatchJob struct {
	correlationID uint64
	handler       HandlerFunc
	request       *magictunnelv1.MagicTunnelRequest
}

// dispatchResult is the outcome of invoking a dispatchJob's handler,
// delivered back to a resultSink by the invoke worker that produced it.
type dispatchResult struct {
	correlationID uint64
	response      []byte
	err           error
}

// resultSink delivers the outcome of a dispatched job back across whatever
// boundary invokePool's caller is running against.
type resultSink interface {
	sendDispatchResult(result dispatchResult)
}

// invokePool runs the goroutine pool that invokes dispatch handlers
// concurrently and reports their outcomes to a resultSink, in FIFO delivery
// order per handler but not necessarily across handlers.
//
// It owns the full lifecycle of that pipeline: accepting jobs, running them,
// and draining whatever is left queued on shutdown so that every accepted
// job is answered exactly once.
type invokePool struct {
	dispatchQueue chan dispatchJob
	stop          chan struct{}
	wg            sync.WaitGroup

	// dispatchMu guards accepting, and is held over the enqueue onto
	// dispatchQueue, so that the queue contents become final the moment
	// shutdown clears accepting: an enqueue blocked here wakes to
	// accepting == false and is refused rather than queued for a worker that
	// is no longer there to answer it.
	dispatchMu sync.Mutex
	accepting  bool

	sink resultSink
}

// newInvokePool creates an invokePool that reports results to sink. Callers
// must call start before enqueueing any jobs.
func newInvokePool(sink resultSink) *invokePool {
	return &invokePool{
		dispatchQueue: make(chan dispatchJob, dispatchQueueCap),
		stop:          make(chan struct{}),
		accepting:     true,
		sink:          sink,
	}
}

// start spins up invokeWorkerCount invoke workers.
func (p *invokePool) start() {
	p.wg.Add(invokeWorkerCount)
	for range invokeWorkerCount {
		go p.invokeWorker()
	}
}

// enqueue offers job onto dispatchQueue, reporting false if the pool is no
// longer accepting work or the queue is full.
func (p *invokePool) enqueue(job dispatchJob) bool {
	p.dispatchMu.Lock()
	defer p.dispatchMu.Unlock()

	if !p.accepting {
		return false
	}

	select {
	case p.dispatchQueue <- job:
		return true
	default:
		return false
	}
}

// shutdown stops the pool from accepting new work, signals the workers to
// drain whatever is already queued and exit, and blocks until they have.
func (p *invokePool) shutdown() {
	p.dispatchMu.Lock()
	p.accepting = false
	p.dispatchMu.Unlock()

	close(p.stop)
	p.wg.Wait()
}

// invokeWorker is one of invokeWorkerCount goroutines draining dispatchQueue
// concurrently, invoking each job's handler and delivering the outcome to
// sink, until stop is closed.
func (p *invokePool) invokeWorker() {
	defer p.wg.Done()
	for {
		select {
		case job := <-p.dispatchQueue:
			p.invokeJob(job)
		case <-p.stop:
			p.drainDispatchQueue()
			return
		}
	}
}

// drainDispatchQueue answers the jobs left in dispatchQueue before
// invokeWorker exits.
//
// libdd_rc.h requires exactly one rc_conn_dispatch_result call per payload
// delivered through DispatchCb, so a queued job cannot simply be discarded
// once stop is closed.
func (p *invokePool) drainDispatchQueue() {
	for {
		select {
		case job := <-p.dispatchQueue:
			p.invokeJob(job)
		default:
			return
		}
	}
}

// invokeJob invokes job.handler with the request payload decoded and routed
// by goDispatchCb, and delivers the outcome to sink.
//
// DispatchRequestPayload.connection_id is intentionally not inspected here
// (nor by goDispatchCb): validating it against the server-assigned
// connection is rc-x509-client's responsibility once that part of the
// protocol is implemented, not the Go host's.
func (p *invokePool) invokeJob(job dispatchJob) {
	response, err := invokeHandler(job)
	p.sink.sendDispatchResult(dispatchResult{correlationID: job.correlationID, response: response, err: err})
}

// invokeHandler calls the handler registered for the job's uri, converting a
// panic in that caller-supplied code into an error.
//
// A panic must not escape: it would take down the dispatch worker, leaving
// this payload and every payload queued behind it for this connection without
// the rc_conn_dispatch_result call the client library is waiting for.
func invokeHandler(job dispatchJob) (response []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			response = nil
			err = fmt.Errorf("ddrc: dispatch handler panicked: %v", r)
		}
	}()

	return job.handler(job.correlationID, job.request.GetRequest())
}
