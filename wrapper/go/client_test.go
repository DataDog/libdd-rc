package libddrc

// Copyright 2026-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/libdd-rc/wrapper/go/internal/testproto"
	"google.golang.org/protobuf/proto"
)

type mockSender struct {
	mu                sync.Mutex
	data              [][]byte
	sendError         error
	replacementSender func(context.Context, []byte) error
}

func (m *mockSender) Send(ctx context.Context, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.replacementSender != nil {
		return m.replacementSender(ctx, data)
	}

	if m.sendError != nil {
		return m.sendError
	}

	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	m.data = append(m.data, dataCopy)

	return nil
}

func (m *mockSender) GetSentData() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][]byte{}, m.data...)
}

func (m *mockSender) SetSendError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendError = err
}

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}
	defer client.Close()

	if client.cCtx == nil {
		t.Fatal("client.ctx is nil")
	}
}

func TestClientClose(t *testing.T) {
	client := NewClient()
	err := client.Close()
	if err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}

	if !client.closed {
		t.Fatal("client not marked as closed")
	}

	err = client.Close()
	if err != nil {
		t.Fatalf("Second Close() returned error: %v", err)
	}
}

func TestClientNewConnection(t *testing.T) {
	client := NewClient()
	defer client.Close()

	sender := &mockSender{}
	conn, err := client.NewConnection(sender)
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}
	if conn == nil {
		t.Fatal("NewConnection() returned nil connection")
	}

	if conn.IsClosed() {
		t.Fatalf("new connection should not be closed")
	}
	if conn.IsConnected() {
		t.Fatalf("new connection should not be connected")
	}
	conn.Disconnect()

	if conn.IsConnected() {
		t.Fatalf("new connection should not be connected")
	}
	if conn.IsClosed() {
		t.Fatalf("new connection should not be closed")
	}

	conn.Close()
	if !conn.IsClosed() {
		t.Fatalf("new connection should be closed")
	}

	// I can call close again
	conn.Close()
	if !conn.IsClosed() {
		t.Fatalf("new connection should still be closed")
	}

	err = conn.Connect(context.TODO())
	if err != ErrConnectionClosed {
		t.Fatalf("Connect() on closed connection should return ErrConnectionClosed, got: %v", err)
	}

}

func TestClientNewConnectionWithoutSender(t *testing.T) {
	client := NewClient()
	defer client.Close()

	_, err := client.NewConnection(nil)
	if !errors.Is(err, ErrNoSender) {
		t.Fatalf("NewConnection(nil) should return ErrNoSender, got: %v", err)
	}
}

func TestClientNewConnectionAfterClose(t *testing.T) {
	client := NewClient()
	client.Close()

	sender := &mockSender{}
	_, err := client.NewConnection(sender)
	if !errors.Is(err, ErrClientClosed) {
		t.Fatalf("NewConnection() after Close() should return ErrClientClosed, got: %v", err)
	}
}

func TestConnectionConnect(t *testing.T) {
	client := NewClient()
	defer client.Close()

	sender := &mockSender{}
	conn, err := client.NewConnection(sender)
	if err != nil {
		t.Fatalf("NewConnection() failed: %v", err)
	}
	defer func() {
		conn.Disconnect()
		conn.Close()
	}()

	ctx := context.Background()
	err = conn.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}

	if !conn.IsConnected() {
		t.Fatal("connection not marked as connected")
	}
}

func TestConnectionConnectTwice(t *testing.T) {
	client := NewClient()
	defer client.Close()

	sender := &mockSender{}
	conn, _ := client.NewConnection(sender)
	defer func() {
		conn.Disconnect()
		conn.Close()
	}()

	ctx := context.Background()
	conn.Connect(ctx)
	err := conn.Connect(ctx)
	if err != nil {
		t.Fatalf("Second Connect() returned error: %v", err)
	}
}

func TestConnectionReceive(t *testing.T) {
	client := NewClient()
	defer client.Close()
	data := []byte{0x01, 0x02, 0x03, 0x04}

	sender := &mockSender{}
	conn, _ := client.NewConnection(sender)

	err := conn.Receive(data)
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Receive() before Connect() should return ErrNotConnected, got: %v", err)
	}

	ctx := context.Background()
	conn.Connect(ctx)

	err = conn.Receive(data)
	if err != nil {
		t.Fatalf("Receive() returned error: %v", err)
	}

	err = conn.Disconnect()
	if err != nil {
		t.Fatalf("Disconnect() returned error: %v", err)
	}

	err = conn.Receive(data)
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Receive() after Close() should return ErrConnectionClosed, got: %v", err)
	}

	conn.Close()
	err = conn.Receive(data)
	if !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("Receive() after Close() should return ErrConnectionClosed, got: %v", err)
	}
}

func TestConnectionReceiveEmptyData(t *testing.T) {
	client := NewClient()
	defer client.Close()

	sender := &mockSender{}
	conn, _ := client.NewConnection(sender)
	defer func() {
		conn.Disconnect()
		conn.Close()
	}()

	ctx := context.Background()
	conn.Connect(ctx)

	err := conn.Receive([]byte{})
	if err == nil {
		t.Fatal("Receive() with empty data should return an error")
	}
}

func TestConnectionDisconnect(t *testing.T) {
	client := NewClient()
	defer client.Close()

	sender := &mockSender{}
	conn, _ := client.NewConnection(sender)
	defer conn.Close()

	ctx := context.Background()
	conn.Connect(ctx)

	err := conn.Disconnect()
	if err != nil {
		t.Fatalf("Disconnect() returned error: %v", err)
	}

	if conn.IsConnected() {
		t.Fatal("connection still marked as connected after Disconnect()")
	}
}

func TestConnectionCloseWithoutDisconnect(t *testing.T) {
	client := NewClient()
	defer client.Close()

	sender := &mockSender{}
	conn, _ := client.NewConnection(sender)

	ctx := context.Background()
	conn.Connect(ctx)

	err := conn.Close()
	if err == nil {
		t.Fatal("Close() without Disconnect() should return an error")
	}

	conn.Disconnect()
	err = conn.Close()
	if err != nil {
		t.Fatalf("Close() after Disconnect() returned error: %v", err)
	}
}

func TestConnectionLifecycle(t *testing.T) {
	client := NewClient()
	defer client.Close()

	sender := &mockSender{}
	conn, err := client.NewConnection(sender)
	if err != nil {
		t.Fatalf("NewConnection() failed: %v", err)
	}

	ctx := context.Background()
	if err := conn.Connect(ctx); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}

	testData := []byte{0x01, 0x02, 0x03, 0x04}
	if err := conn.Receive(testData); err != nil {
		t.Fatalf("Receive() failed: %v", err)
	}

	if err := conn.Disconnect(); err != nil {
		t.Fatalf("Disconnect() failed: %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
}

func TestMultipleConnections(t *testing.T) {
	client := NewClient()
	defer client.Close()

	sender1 := &mockSender{}
	sender2 := &mockSender{}

	conn1, err := client.NewConnection(sender1)
	if err != nil {
		t.Fatalf("NewConnection() 1 failed: %v", err)
	}

	conn2, err := client.NewConnection(sender2)
	if err != nil {
		t.Fatalf("NewConnection() 2 failed: %v", err)
	}

	ctx := context.Background()
	conn1.Connect(ctx)
	conn2.Connect(ctx)

	data := []byte{0x01, 0x02, 0x03}
	conn1.Receive(data)
	conn2.Receive(data)

	conn1.Disconnect()
	conn2.Disconnect()

	conn1.Close()
	conn2.Close()
}

func TestSenderFunc(t *testing.T) {
	client := newTestClient()
	defer client.Close()

	var called bool
	var sentData []byte
	var mu sync.Mutex

	senderFunc := SenderFunc(func(ctx context.Context, data []byte) error {
		mu.Lock()
		defer mu.Unlock()
		called = true
		sentData = append([]byte{}, data...)
		return nil
	})

	conn, err := client.NewConnection(senderFunc)
	if err != nil {
		t.Fatalf("NewConnection() failed: %v", err)
	}
	defer func() {
		conn.Disconnect()
		conn.Close()
	}()

	ctx := context.Background()
	if err := conn.Connect(ctx); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}

	pingMsg := &testproto.ServerToClient{
		Message: &testproto.ServerToClient_Ping{
			Ping: &testproto.Ping{},
		},
	}

	pingData, err := proto.Marshal(pingMsg)
	if err != nil {
		t.Fatalf("Failed to marshal ping message: %v", err)
	}

	if err := conn.Receive(pingData); err != nil {
		t.Fatalf("Receive() failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if !called {
		t.Fatal("SenderFunc was not called")
	}

	if len(sentData) == 0 {
		t.Fatal("SenderFunc was called with empty data")
	}
}

func TestSenderError(t *testing.T) {
	client := NewClient()
	defer client.Close()

	sender := &mockSender{}
	sender.SetSendError(errors.New("network error"))

	conn, _ := client.NewConnection(sender)
	defer func() {
		conn.Disconnect()
		conn.Close()
	}()

	ctx := context.Background()
	conn.Connect(ctx)

	time.Sleep(10 * time.Millisecond)

	conn.Disconnect()
}

func TestConnectionContextCancellation(t *testing.T) {
	client := NewClient()
	defer client.Close()

	sender := &mockSender{}
	conn, _ := client.NewConnection(sender)
	defer func() {
		conn.Disconnect()
		conn.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	conn.Connect(ctx)

	cancel()

	time.Sleep(10 * time.Millisecond)

	conn.Disconnect()
}

func TestEchoHarness(t *testing.T) {
	client := newTestClient()
	if client == nil {
		t.Fatal("newTestClient() returned nil")
	}
	defer client.Close()

	if client.cCtx == nil {
		t.Fatal("client.ctx is nil")
	}

	sender := &mockSender{}
	conn, err := client.NewConnection(sender)
	if err != nil {
		t.Fatalf("NewConnection() failed: %v", err)
	}
	defer func() {
		conn.Disconnect()
		conn.Close()
	}()

	ctx := context.Background()
	if err := conn.Connect(ctx); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}

	testData := []byte{0x01, 0x02, 0x03, 0x04}
	if err := conn.Receive(testData); err != nil {
		t.Fatalf("Receive() failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	sentData := sender.GetSentData()
	if len(sentData) == 0 {
		t.Fatal("Echo harness did not send response")
	}

	var response testproto.ClientToServer
	if err := proto.Unmarshal(sentData[0], &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if _, ok := response.Message.(*testproto.ClientToServer_Pong); !ok {
		t.Fatalf("Expected Pong response, got: %T", response.Message)
	}
}
