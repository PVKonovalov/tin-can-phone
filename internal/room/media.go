package room

import (
	"sync"

	"github.com/PVKonovalov/tin-can-phone/internal/protocol"
)

// UnavailableMedia is the MediaHandler used until the SFU exists: it answers
// every media message with error {code: "media-unavailable"}.
type UnavailableMedia struct {
	mu    sync.Mutex
	sends map[[2]string]func(protocol.Envelope) error
}

// NewUnavailableMedia returns the stub media handler.
func NewUnavailableMedia() *UnavailableMedia {
	return &UnavailableMedia{sends: map[[2]string]func(protocol.Envelope) error{}}
}

func (u *UnavailableMedia) PeerJoined(roomID, peerID string, send func(protocol.Envelope) error) {
	u.mu.Lock()
	u.sends[[2]string{roomID, peerID}] = send
	u.mu.Unlock()
}

func (u *UnavailableMedia) PeerLeft(roomID, peerID string) {
	u.mu.Lock()
	delete(u.sends, [2]string{roomID, peerID})
	u.mu.Unlock()
}

func (u *UnavailableMedia) Signal(roomID, peerID string, msg protocol.Envelope) {
	u.mu.Lock()
	send := u.sends[[2]string{roomID, peerID}]
	u.mu.Unlock()
	if send != nil {
		_ = send(protocol.NewError(peerID, protocol.ErrMediaUnavailable,
			"media is not available on this server yet (got "+msg.Type+")"))
	}
}
