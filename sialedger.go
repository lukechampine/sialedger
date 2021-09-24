package sialedger // import "lukechampine.com/sialedger"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/karalabe/hid"
	"go.sia.tech/siad/types"
)

type hidFramer struct {
	rw  io.ReadWriter
	seq uint16
	buf [64]byte
	pos int
}

func (hf *hidFramer) Reset() {
	hf.seq = 0
}

func (hf *hidFramer) Write(p []byte) (int, error) {
	// split into 64-byte chunks
	chunk := make([]byte, 64)
	binary.BigEndian.PutUint16(chunk[:2], 0x0101)
	chunk[2] = 0x05
	var seq uint16
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(len(p)))
	buf.Write(p)
	for buf.Len() > 0 {
		binary.BigEndian.PutUint16(chunk[3:5], seq)
		n, _ := buf.Read(chunk[5:])
		if n, err := hf.rw.Write(chunk[:5+n]); err != nil {
			return n, err
		}
		seq++
	}
	return len(p), nil
}

func (hf *hidFramer) Read(p []byte) (int, error) {
	if hf.seq > 0 && hf.pos != 64 {
		// drain buf
		n := copy(p, hf.buf[hf.pos:])
		hf.pos += n
		return n, nil
	}
	// read next 64-byte packet
	if n, err := hf.rw.Read(hf.buf[:]); err != nil {
		return 0, err
	} else if n != 64 {
		panic("read less than 64 bytes from HID")
	}
	// parse header
	channelID := binary.BigEndian.Uint16(hf.buf[:2])
	commandTag := hf.buf[2]
	seq := binary.BigEndian.Uint16(hf.buf[3:5])
	if channelID != 0x0101 {
		return 0, fmt.Errorf("bad channel ID 0x%x", channelID)
	} else if commandTag != 0x05 {
		return 0, fmt.Errorf("bad command tag 0x%x", commandTag)
	} else if seq != hf.seq {
		return 0, fmt.Errorf("bad sequence number %v (expected %v)", seq, hf.seq)
	}
	hf.seq++
	// start filling p
	n := copy(p, hf.buf[5:])
	hf.pos = 5 + n
	return n, nil
}

type apdu struct {
	CLA     byte
	INS     byte
	P1, P2  byte
	Payload []byte
}

type apduFramer struct {
	hf  *hidFramer
	buf [2]byte // to read APDU length prefix
}

func (af *apduFramer) Exchange(a apdu) ([]byte, error) {
	if len(a.Payload) > 255 {
		panic("APDU payload cannot exceed 255 bytes")
	}
	af.hf.Reset()
	data := append([]byte{
		a.CLA,
		a.INS,
		a.P1, a.P2,
		byte(len(a.Payload)),
	}, a.Payload...)
	if _, err := af.hf.Write(data); err != nil {
		return nil, err
	}

	// read APDU length
	if _, err := io.ReadFull(af.hf, af.buf[:]); err != nil {
		return nil, err
	}
	// read APDU payload
	respLen := binary.BigEndian.Uint16(af.buf[:2])
	resp := make([]byte, respLen)
	_, err := io.ReadFull(af.hf, resp)
	return resp, err
}

// NanoS represents a connected Nano S device.
type NanoS struct {
	device *apduFramer
}

// An ErrCode is returned by the various Sia app commands. The special code
// 0x9000 ("success") is converted to nil.
type ErrCode uint16

func (c ErrCode) Error() string {
	return fmt.Sprintf("Error code 0x%x", uint16(c))
}

const codeSuccess = 0x9000
const codeUserRejected = 0x6985
const codeInvalidParam = 0x6b01

var errUserRejected = errors.New("user denied request")
var errInvalidParam = errors.New("invalid request parameters")

// Exchange exchanges an arbitrary command with the Nano S.
func (n *NanoS) Exchange(cmd byte, p1, p2 byte, data []byte) (resp []byte, err error) {
	resp, err = n.device.Exchange(apdu{
		CLA:     0xe0,
		INS:     cmd,
		P1:      p1,
		P2:      p2,
		Payload: data,
	})
	if err != nil {
		return nil, err
	} else if len(resp) < 2 {
		return nil, errors.New("APDU response missing status code")
	}
	code := binary.BigEndian.Uint16(resp[len(resp)-2:])
	resp = resp[:len(resp)-2]
	switch code {
	case codeSuccess:
		err = nil
	case codeUserRejected:
		err = errUserRejected
	case codeInvalidParam:
		err = errInvalidParam
	default:
		err = ErrCode(code)
	}
	return
}

const (
	cmdGetVersion   = 0x01
	cmdGetPublicKey = 0x02
	cmdSignHash     = 0x04
	cmdCalcTxnHash  = 0x08

	p1First = 0x00
	p1More  = 0x80

	p2DisplayAddress = 0x00
	p2DisplayPubkey  = 0x01
	p2DisplayHash    = 0x00
	p2SignHash       = 0x01
)

// GetVersion executes the getVersion command, returning the version of the Sia
// app running on the Nano S.
func (n *NanoS) GetVersion() (version string, err error) {
	resp, err := n.Exchange(cmdGetVersion, 0, 0, nil)
	if err != nil {
		return "", err
	} else if len(resp) != 3 {
		return "", errors.New("version has wrong length")
	}
	return fmt.Sprintf("v%d.%d.%d", resp[0], resp[1], resp[2]), nil
}

// GetAddress executes the getPublicKey command, prompting the user to approve
// the generation of the specified address and public key. If approved, the
// address (or public key) is displayed on the device and returned.
func (n *NanoS) GetAddress(index uint32, displayPubKey bool) (addr types.UnlockHash, spk types.SiaPublicKey, err error) {
	encIndex := make([]byte, 4)
	binary.LittleEndian.PutUint32(encIndex, index)

	var p2 byte = p2DisplayAddress
	if displayPubKey {
		p2 = p2DisplayPubkey
	}
	resp, err := n.Exchange(cmdGetPublicKey, 0, p2, encIndex)
	if err != nil {
		return types.UnlockHash{}, types.SiaPublicKey{}, err
	}
	if err := addr.LoadString(string(resp[32:])); err != nil {
		return types.UnlockHash{}, types.SiaPublicKey{}, err
	}
	spk.Algorithm = types.SignatureEd25519
	spk.Key = make([]byte, 32)
	if copy(spk.Key, resp) != len(spk.Key) {
		return types.UnlockHash{}, types.SiaPublicKey{}, errors.New("pubkey has wrong length")
	}
	return
}

// SignHash executes the signHash command, prompting the user to sign the
// supplied hash with the specified key. If approved, the signature is returned.
func (n *NanoS) SignHash(hash [32]byte, keyIndex uint32) (sig [64]byte, err error) {
	encIndex := make([]byte, 4)
	binary.LittleEndian.PutUint32(encIndex, keyIndex)

	resp, err := n.Exchange(cmdSignHash, 0, 0, append(encIndex, hash[:]...))
	if err != nil {
		return [64]byte{}, err
	}
	if copy(sig[:], resp) != len(sig) {
		return [64]byte{}, errors.New("signature has wrong length")
	}
	return
}

// CalcTxnHash executes the calcTxnHash command, prompting the user to review
// the supplied transaction. If approved, the sighash for the specified
// transaction signature is displayed on the screen and returned.
func (n *NanoS) CalcTxnHash(txn types.Transaction, sigIndex uint16) (hash [32]byte, err error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // keyIndex
	binary.Write(buf, binary.LittleEndian, sigIndex)
	txn.MarshalSia(buf)

	var resp []byte
	for buf.Len() > 0 {
		var p1 byte = p1More
		if resp == nil {
			p1 = p1First
		}
		resp, err = n.Exchange(cmdCalcTxnHash, p1, p2DisplayHash, buf.Next(255))
		if err != nil {
			return [32]byte{}, err
		}
	}
	if copy(hash[:], resp) != len(hash) {
		return [32]byte{}, errors.New("hash has wrong length")
	}
	return
}

// SignTxn executes the calcTxnHash command with the SignHash flag, prompting
// the user to review and sign the supplied transaction. If approved, the
// specified sighash is signed and returned.
func (n *NanoS) SignTxn(txn types.Transaction, sigIndex uint16, keyIndex uint32) (sig [64]byte, err error) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, keyIndex)
	binary.Write(&buf, binary.LittleEndian, sigIndex)
	txn.MarshalSia(&buf)

	var resp []byte
	for buf.Len() > 0 {
		var p1 byte = p1More
		if resp == nil {
			p1 = p1First
		}
		resp, err = n.Exchange(cmdCalcTxnHash, p1, p2SignHash, buf.Next(255))
		if err != nil {
			return [64]byte{}, err
		}
	}
	if copy(sig[:], resp) != len(sig) {
		return [64]byte{}, errors.New("signature has wrong length")
	}
	return
}

// OpenNanoS detects and connects to a Nano S device.
func OpenNanoS() (*NanoS, error) {
	const (
		ledgerVendorID       = 0x2c97
		ledgerNanoSProductID = 0x0001
		//ledgerUsageID        = 0xffa0
	)

	// search for Nano S
	devices := hid.Enumerate(ledgerVendorID, ledgerNanoSProductID)
	if len(devices) == 0 {
		return nil, errors.New("Nano S not detected")
	} else if len(devices) > 1 {
		return nil, errors.New("Unexpected error -- Is the Sia wallet app running?")
	}

	// open the device
	device, err := devices[0].Open()
	if err != nil {
		return nil, err
	}

	// wrap raw device I/O in HID+APDU protocols
	return &NanoS{
		device: &apduFramer{
			hf: &hidFramer{
				rw: device,
			},
		},
	}, nil
}
