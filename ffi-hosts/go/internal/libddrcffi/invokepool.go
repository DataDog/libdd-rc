package libddrcffi

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	magictunnelv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel"
)

const (
	dispatchQueueCap = 100

	// invokeWorkerCount is the size of the goroutine pool that invokes
	// handlers concurrently.
	invokeWorkerCount = 8

	// defaultHandlerTimeout is the maximum duration a HandlerFunc invocation
	// is allowed to run before invokeHandler reports a dispatch timeout.
	defaultHandlerTimeout = 30 * time.Second
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
	sendDispatchError(correlationID uint64, errorCode int)
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

	// dispatchMu guards accepting and wg, and is held over the enqueue onto
	// dispatchQueue, so that the queue contents become final the moment
	// shutdown clears accepting: an enqueue blocked here wakes to
	// accepting == false and is refused rather than queued for a worker that
	// is no longer there to answer it.
	//
	// wg tracks jobs that have been accepted to ensure that the invokePool
	// does not close without reporting pending HandlerFuncs. They are given the
	// chance to return their result, or timeout and us report that error.
	//
	// This protects against a use after free right now, as the sink methods are
	// unfortunately tied directly to the Connection. The connection is enforced to
	// order things properly on close, shutting down this pool before freeing the
	// pointer. If that is respected, this wg prevents use after free for pending
	// jobs. A future refactor should untangle these concerns relaxing the need for
	// strict ordering.
	dispatchMu sync.Mutex
	accepting  bool
	wg         sync.WaitGroup

	sink resultSink

	// handlerTimeout is the maximum duration a HandlerFunc invocation is
	// allowed to run. Tests may override this to a short duration to
	// exercise the timeout path without waiting on defaultHandlerTimeout.
	handlerTimeout time.Duration
}

// newInvokePool creates an invokePool that reports results to sink. Callers
// must call start before enqueueing any jobs.
func newInvokePool(sink resultSink) *invokePool {
	return &invokePool{
		dispatchQueue:  make(chan dispatchJob, dispatchQueueCap),
		stop:           make(chan struct{}),
		accepting:      true,
		sink:           sink,
		handlerTimeout: defaultHandlerTimeout,
	}
}

// start spins up invokeWorkerCount invoke workers.
func (p *invokePool) start() {
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
		p.wg.Add(1)
		return true
	default:
		return false
	}
}

// shutdown stops the pool from accepting new work, signals the workers to
// drain whatever is already queued, and blocks until every accepted job has
// been answered.
//
// It does not wait for the invoke worker goroutines themselves to return: a
// HandlerFunc that ignores its context can block one forever, and that
// goroutine is left to leak rather than holding up shutdown. In that scenario
// shutdown() still waits to report the timeout to the backend for tracking purposoes.
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
	response, err := p.invokeHandler(job)

	// If the handler timed out, the timeout watcher already reported this
	// as a dispatch error and released wg for this job, so we should not
	// sendDispatchResult nor release wg again here.
	if err == errHandlerTimeout {
		return
	}

	p.sink.sendDispatchResult(dispatchResult{correlationID: job.correlationID, response: response, err: err})
	p.wg.Done()
}

// errHandlerTimeout lets us catch that the err from invokeHandler
// wasn't from the handler itself and instead us detecting a HandlerFunc
// took too long.
var errHandlerTimeout = errors.New("ddrc: handler timeout")

// invokeHandler calls the handler registered for the job's uri, converting a
// panic in that caller-supplied code into an error.
//
// A panic must not escape: it would take down the dispatch worker, leaving
// this payload and every payload queued behind it for this connection without
// the rc_conn_dispatch_result call the client library is waiting for.
func (p *invokePool) invokeHandler(job dispatchJob) (response []byte, err error) {
	var completed atomic.Bool

	defer func() {
		if r := recover(); r != nil {
			response = nil
			// Check to see if this panic beat the timeout. If it did not, we need to
			// inform there's been a timeout.
			swapped := completed.CompareAndSwap(false, true)
			if !swapped {
				err = errHandlerTimeout
			} else {
				err = fmt.Errorf("ddrc: dispatch handler panicked: %v", r)
			}
		}
	}()

	handlerCtx, cancel := context.WithTimeout(context.Background(), p.handlerTimeout)
	defer cancel()

	// Wait until the context is completed, if it completed because of a normal operation,
	// then we'll have already set the completed atomic bool to true. If we end up performing
	// the swap, then it means the context timed out and we need to send this as a dispatch error.
	//
	// This goroutine is deliberately not joined by p.wg: if job.handler
	// below never returns, this is the only goroutine that will ever answer
	// this job, and it does so within handlerTimeout regardless of whether
	// the worker calling job.handler ever comes back. wg.Done is called
	// only once sendDispatchError has actually returned, so shutdown can't
	// observe this job as answered while that call is still in flight.
	go func() {
		<-handlerCtx.Done()
		swapped := completed.CompareAndSwap(false, true)

		// It wasn't completed yet, so we need to report the dispatch timeout
		if swapped {
			p.sink.sendDispatchError(job.correlationID, DispatchErrorTimeout)
			p.wg.Done()
		}
	}()

	response, err = job.handler(handlerCtx, job.correlationID, job.request.GetRequest())

	// Check to see if we beat the timeout, and are able to send this as normal dispatch
	// result to the backend.
	swapped := completed.CompareAndSwap(false, true)
	if !swapped {
		return nil, errHandlerTimeout
	}

	return response, err
}
