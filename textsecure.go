// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

// Package textsecure implements the TextSecure client protocol.
package textsecure

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/zmanian/textsecure/axolotl"
	"github.com/zmanian/textsecure/protobuf"
	"log"
	"mime"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

// Generate a random 16 byte string used for HTTP Basic Authentication to the server
func generatePassword() string {
	b := make([]byte, 16)
	randBytes(b[:])
	return base64EncWithoutPadding(b)
}

// Generate a random 14 bit integer
func generateRegistrationID() uint32 {
	return randUint32() & 0x3fff
}

// Generate a 256 bit AES and a 160 bit HMAC-SHA1 key
// to be used to secure the communication with the server
func generateSignalingKey() []byte {
	b := make([]byte, 52)
	randBytes(b[:])
	return b
}

// Base64-encodes without padding the result
func base64EncWithoutPadding(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	return strings.TrimRight(s, "=")
}

// Base64-decodes a non-padded string
func base64DecodeNonPadded(s string) []byte {
	if len(s)%4 != 0 {
		s = s + strings.Repeat("=", 4-len(s)%4)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func encodeKey(key [32]byte) string {
	return base64EncWithoutPadding(append([]byte{5}, key[:]...))
}

func decodeKey(s string) []byte {
	b := base64DecodeNonPadded(s)
	if len(b) != 33 || b[0] != 5 {
		log.Fatal("Public key not formatted correctly")
	}
	return b[1:]
}

func decodeSignature(s string) []byte {
	b := base64DecodeNonPadded(s)
	if len(b) != 64 {
		log.Fatal("Signature not 64 bytes")
	}
	return b
}

func needsRegistration() bool {
	return !textSecureStore.valid()
}

var identityKey *axolotl.IdentityKeyPair

// SendMessage sends the given text message to the given contact.
func SendMessage(tel, msg string) error {
	err := sendMessage(tel, msg, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// SendFileAttachment sends the contents of a file, associated
// with an optional message to a given contact.
func SendFileAttachment(tel, msg string, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}

	ct := mime.TypeByExtension(filepath.Ext(path))
	a, err := uploadAttachment(f, ct)
	if err != nil {
		return err
	}
	err = sendMessage(tel, msg, nil, a)
	if err != nil {
		return err
	}
	return nil
}

// Message represents a message received from the peer.
// It can optionally include attachments and be sent to a group.
type Message struct {
	source      string
	message     string
	attachments [][]byte
	group       string
}

// Source returns the ID of the sender of the message.
func (m *Message) Source() string {
	return m.source
}

// Message returns the message body.
func (m *Message) Message() string {
	return m.message
}

// Attachments returns the list of attachments on the message.
func (m *Message) Attachments() [][]byte {
	return m.attachments
}

// Group returns the group name or empty.
func (m *Message) Group() string {
	return m.group
}

// Client contains application specific data and callbacks.
type Client struct {
	RootDir            string
	ReadLine           func(string) string
	GetStoragePassword func() string
	GetConfig          func() (*Config, error)
	GetLocalContacts   func() ([]Contact, error)
	MessageHandler     func(*Message)
}

var (
	config *Config
	client *Client
)

// Setup initializes the package.
func Setup(c *Client) error {
	var err error

	client = c

	config, err = loadConfig()
	if err != nil {
		return err
	}

	setupStore()
	
	if needsRegistration() {
		registrationInfo.registrationID = generateRegistrationID()
		textSecureStore.SetLocalRegistrationID(registrationInfo.registrationID)

		registrationInfo.password = generatePassword()
		textSecureStore.storeHTTPPassword(registrationInfo.password)

		registrationInfo.signalingKey = generateSignalingKey()
		textSecureStore.storeHTTPSignalingKey(registrationInfo.signalingKey)

		identityKey = axolotl.GenerateIdentityKeyPair()
		textSecureStore.SetIdentityKeyPair(identityKey)

		setupTransporter()
		err := registerDevice()
		if err != nil {
			return err
		}
	}
	registrationInfo.registrationID = textSecureStore.GetLocalRegistrationID()
	registrationInfo.password = textSecureStore.loadHTTPPassword()
	registrationInfo.signalingKey = textSecureStore.loadHTTPSignalingKey()
	setupTransporter()
	identityKey = textSecureStore.GetIdentityKeyPair()
	return nil
}

func registerDevice() error {
	vt := config.VerificationType
	if vt == "" {
		vt = "sms"
	}
	code, err := requestCode(config.Tel, vt)
	if err != nil {
		return err
	}
	if code == "" {
		code = readLine("Enter verification number (without the '-')>")
	}
	code = strings.Replace(code, "-", "", -1)
	err = verifyCode(code)
	if err != nil {
		return err
	}
	generatePreKeys()
	generatePreKeyState()
	err = registerPreKeys2()
	if err != nil {
		return err
	}
	log.Println("Registration done")
	return nil
}

func ShowFingerprint(id string) {
	if id == "me" || id == "self" || id == config.Tel {
		key := textSecureStore.GetIdentityKeyPair()
		log.Printf("Fingerprint for %s is % 0X", id, key.PublicKey.ECPublicKey.Key())
	} else {
		key := textSecureStore.GetUserIdentityKeyPair(recID(id))
		log.Printf("Fingerprint for %s is % 0X", id, key.PublicKey.ECPublicKey.Key())
	}
}

func handleReceipt(ipms *textsecure.IncomingPushMessageSignal) {
	//log.Printf("Receipt %+v\n", ipms)
}

func recID(source string) string {
	return source[1:]
}

// handleMessageBody unmarshals the message and calls the client callbacks
func handleMessageBody(src string, b []byte) error {
	b = stripPadding(b)
	pmc := &textsecure.PushMessageContent{}
	err := proto.Unmarshal(b, pmc)
	if err != nil {
		return err
	}
	atts, err := handleAttachments(pmc)
	if err != nil {
		return err
	}

	gr, err := handleGroups(src, pmc)
	if err != nil {
		return err
	}

	msg := &Message{
		source:      src,
		message:     pmc.GetBody(),
		attachments: atts,
		group:       gr,
	}

	if client.MessageHandler != nil {
		client.MessageHandler(msg)
	}
	return nil
}

// Authenticate and decrypt a received message
func handleReceivedMessage(msg []byte) error {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("PANIC: %s\n", err)
			log.Printf("%s\n", debug.Stack())
		}
	}()

	macpos := len(msg) - 10
	tmac := msg[macpos:]
	aesKey := registrationInfo.signalingKey[:32]
	macKey := registrationInfo.signalingKey[32:]
	if !axolotl.ValidTruncMAC(msg[:macpos], tmac, macKey) {
		return errors.New("Invalid MAC for Incoming Message")
	}
	ciphertext := msg[1:macpos]

	plaintext := axolotl.Decrypt(aesKey, ciphertext)
	ipms := &textsecure.IncomingPushMessageSignal{}
	err := proto.Unmarshal(plaintext, ipms)
	if err != nil {
		return err
	}
	//log.Printf("%s %s %d\n", ipms.GetType(), ipms.GetSource(), ipms.GetSourceDevice())
	recid := recID(ipms.GetSource())
	sc := axolotl.NewSessionCipher(textSecureStore, textSecureStore, textSecureStore, textSecureStore, recid, ipms.GetSourceDevice())
	switch *ipms.Type {
	case textsecure.IncomingPushMessageSignal_RECEIPT:
		handleReceipt(ipms)
		return nil
	case textsecure.IncomingPushMessageSignal_CIPHERTEXT:
		wm, err := axolotl.LoadWhisperMessage(ipms.GetMessage())
		if err != nil {
			return err
		}
		b, err := sc.SessionDecryptWhisperMessage(wm)
		if err != nil {
			return err
		}
		err = handleMessageBody(ipms.GetSource(), b)
		if err != nil {
			return err
		}

	case textsecure.IncomingPushMessageSignal_PLAINTEXT:
		pmc := &textsecure.PushMessageContent{}
		err = proto.Unmarshal(ipms.GetMessage(), pmc)
		if err != nil {
			return err
		}
	case textsecure.IncomingPushMessageSignal_PREKEY_BUNDLE:
		pkwm, err := axolotl.LoadPreKeyWhisperMessage(ipms.GetMessage())
		if err != nil {
			return err
		}
		b, err := sc.SessionDecryptPreKeyWhisperMessage(pkwm)
		if err != nil {
			return err
		}
		err = handleMessageBody(ipms.GetSource(), b)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("Not implemented %d", *ipms.Type)
	}

	return nil
}
