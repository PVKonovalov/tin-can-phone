// Package protocol defines the signaling wire format shared by the room
// manager, the WebSocket layer and the media (SFU) side.
package protocol

import "encoding/json"

// Envelope is every signaling message. The server always sets From
// (FromServer or the sender's peer ID); a client-supplied From is ignored.
type Envelope struct {
	Type    string          `json:"type"`
	From    string          `json:"from,omitempty"`
	To      string          `json:"to,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Well-known endpoints in From/To.
const (
	FromServer = "server"
	ToSFU      = "sfu"
)

// Message types.
const (
	TypeHello        = "hello"         // C→S {displayName}
	TypeWelcome      = "welcome"       // S→C {peerId, peers, maxPeers}
	TypePeerJoined   = "peer-joined"   // S→C PeerInfo
	TypePeerLeft     = "peer-left"     // S→C {peerId}
	TypePeerState    = "peer-state"    // C→S {muted}; S→C {muted} with From = peer
	TypeOffer        = "offer"         // C↔S, media
	TypeAnswer       = "answer"        // C↔S, media
	TypeICECandidate = "ice-candidate" // C↔S, media
	TypeError        = "error"         // S→C {code, message}
)

// IsMedia reports whether t is routed to the MediaHandler.
func IsMedia(t string) bool {
	return t == TypeOffer || t == TypeAnswer || t == TypeICECandidate
}

// Payloads.
type (
	Hello struct {
		DisplayName string `json:"displayName"`
	}
	PeerInfo struct {
		PeerID      string `json:"peerId"`
		DisplayName string `json:"displayName"`
		Muted       bool   `json:"muted"`
	}
	Welcome struct {
		PeerID   string     `json:"peerId"`
		Peers    []PeerInfo `json:"peers"`
		MaxPeers int        `json:"maxPeers"`
	}
	PeerLeft struct {
		PeerID string `json:"peerId"`
	}
	PeerState struct {
		Muted *bool `json:"muted"` // pointer: required field
	}
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
)

// Error codes sent in TypeError payloads.
const (
	ErrMediaUnavailable = "media-unavailable"
)

// WebSocket close codes.
const (
	CloseGoingAway    = 1001 // server shutting down
	ClosePolicy       = 1008 // send queue overflow (client too slow)
	CloseBadMessage   = 4400 // malformed/unknown message, no hello in time
	CloseRoomNotFound = 4404
	CloseRoomFull     = 4409
	CloseRateLimited  = 4429
)

// MaxMessageBytes is the largest accepted client message.
const MaxMessageBytes = 64 << 10

// New builds an envelope with a JSON-encoded payload.
func New(typ, from, to string, payload any) Envelope {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			panic("protocol: marshal " + typ + ": " + err.Error()) // payloads are our own structs
		}
		raw = b
	}
	return Envelope{Type: typ, From: from, To: to, Payload: raw}
}

// NewError builds an error envelope from the server.
func NewError(to, code, message string) Envelope {
	return New(TypeError, FromServer, to, Error{Code: code, Message: message})
}
