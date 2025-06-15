package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/typosentinel/typosentinel/internal/events"
)

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	eventBus   *events.EventBus
	mu         sync.RWMutex
}

type Client struct {
	hub            *Hub
	conn           *websocket.Conn
	send           chan []byte
	organizationID string
	userID         string
}

type Message struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
}

func NewHub(eventBus *events.EventBus) *Hub {
	hub := &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		eventBus:   eventBus,
	}

	// Subscribe to relevant events
	eventBus.Subscribe(events.PackageScanned, hub.handlePackageScanned)
	eventBus.Subscribe(events.ThreatDetected, hub.handleThreatDetected)
	eventBus.Subscribe(events.BatchCompleted, hub.handleBatchCompleted)
	eventBus.Subscribe(events.PolicyViolation, hub.handlePolicyViolation)

	return hub
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("Client connected: %s (org: %s)", client.userID, client.organizationID)

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			log.Printf("Client disconnected: %s (org: %s)", client.userID, client.organizationID)

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

func (h *Hub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	// Extract organization ID and user ID from query parameters or headers
	organizationID := r.URL.Query().Get("org_id")
	userID := r.URL.Query().Get("user_id")

	if organizationID == "" {
		conn.WriteMessage(websocket.CloseMessage, []byte("Missing organization ID"))
		conn.Close()
		return
	}

	client := &Client{
		hub:            h,
		conn:           conn,
		send:           make(chan []byte, 256),
		organizationID: organizationID,
		userID:         userID,
	}

	client.hub.register <- client

	// Start goroutines for reading and writing
	go client.writePump()
	go client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current message
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte("\n"))
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// Event handlers
func (h *Hub) handlePackageScanned(event *events.Event) error {
	message := Message{
		Type:      "scan_completed",
		Data:      event.Data,
		Timestamp: event.Timestamp,
	}

	return h.broadcastToOrganization(message, event.Data["organization_id"])
}

func (h *Hub) handleThreatDetected(event *events.Event) error {
	message := Message{
		Type:      "threat_detected",
		Data:      event.Data,
		Timestamp: event.Timestamp,
	}

	return h.broadcastToOrganization(message, event.Data["organization_id"])
}

func (h *Hub) handleBatchCompleted(event *events.Event) error {
	message := Message{
		Type:      "batch_completed",
		Data:      event.Data,
		Timestamp: event.Timestamp,
	}

	return h.broadcastToOrganization(message, event.Data["organization_id"])
}

func (h *Hub) handlePolicyViolation(event *events.Event) error {
	message := Message{
		Type:      "policy_violation",
		Data:      event.Data,
		Timestamp: event.Timestamp,
	}

	return h.broadcastToOrganization(message, event.Data["organization_id"])
}

func (h *Hub) broadcastToOrganization(message Message, orgID interface{}) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}

	organizationID, ok := orgID.(string)
	if !ok {
		// Broadcast to all if no specific organization
		h.broadcast <- data
		return nil
	}

	// Send to specific organization clients
	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		if client.organizationID == organizationID {
			select {
			case client.send <- data:
			default:
				close(client.send)
				delete(h.clients, client)
			}
		}
	}

	return nil
}

// Broadcast progress updates for batch operations
func (h *Hub) BroadcastBatchProgress(batchID, organizationID string, progress int, total int) {
	message := Message{
		Type: "batch_progress",
		Data: map[string]interface{}{
			"batch_id":        batchID,
			"organization_id": organizationID,
			"progress":        progress,
			"total":           total,
			"percentage":      float64(progress) / float64(total) * 100,
		},
		Timestamp: time.Now(),
	}

	h.broadcastToOrganization(message, organizationID)
}

// Send real-time scan status updates
func (h *Hub) BroadcastScanStatus(packageName, organizationID, status string, details map[string]interface{}) {
	message := Message{
		Type: "scan_status",
		Data: map[string]interface{}{
			"package_name":    packageName,
			"organization_id": organizationID,
			"status":          status,
			"details":         details,
		},
		Timestamp: time.Now(),
	}

	h.broadcastToOrganization(message, organizationID)
}