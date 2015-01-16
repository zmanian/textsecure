package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"github.com/zmanian/textsecure"
	"golang.org/x/crypto/ssh/terminal"
)

// Simple command line test app for TextSecure.
// It can act as an echo service, send one-off messages and attachments,
// or carry on a conversation with another client

type Session struct {
	to string
}

type Sessions []Session

func findSession(sessions Sessions, recipient string) (int, error) {
	for index, sess := range sessions {
		if sess.to == recipient {
			return index, nil
		}
	}
	return -1, fmt.Errorf("Session not found")
}

var (
	echo          bool
	to            string
	message       string
	attachment    string
	fingerprint   string
	group         bool
	sessions      Sessions
	activeSession *Session
)

func init() {
	flag.BoolVar(&echo, "echo", false, "Act as an echo service")
	flag.StringVar(&to, "to", "", "Contact name to send the message to")
	flag.StringVar(&to, "t", "", "Contact name to send the message to")
	flag.BoolVar(&group, "group", false, "Destination is a group")
	flag.BoolVar(&group, "g", false, "Destination is a group")
	flag.StringVar(&message, "message", "", "Single message to send, then exit")
	flag.StringVar(&message, "m", "", "Single message to send, then exit")
	flag.StringVar(&attachment, "attachment", "", "File to attach")
	flag.StringVar(&attachment, "a", "", "File to attach")
	flag.StringVar(&fingerprint, "fingerprint", "", "Name of contact to get identity key fingerprint")
	flag.StringVar(&fingerprint, "f", "", "Name of contact to get identity key fingerprint")
}

var (
	red   = "\x1b[31m"
	green = "\x1b[32m"
	blue  = "\x1b[34m"
)

func getStoragePassword() string {
	fmt.Printf("Input storage password>")
	password, err := terminal.ReadPassword(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()
	return string(password)
}

// conversationLoop sends messages read from the console
func conversationLoop(isGroup bool) {
	for {
		message := textsecure.ConsoleReadLine(fmt.Sprintf("%s%s>", blue, activeSession.to))
		if message == "" {
			continue
		}
		var err error
		if isGroup {
			err = textsecure.SendGroupMessage(to, message)
		} else {
			err = textsecure.SendMessage(to, message)
		}
		if err != nil {
			log.Println(err)
		}
	}
}

func messageHandler(msg *textsecure.Message) {
	if echo {
		if msg.Group() != "" {
			textsecure.SendGroupMessage(msg.Group(), msg.Message())
			return
		}
		err := textsecure.SendMessage(msg.Source(), msg.Message())
		if err != nil {
			log.Println(err)
		}
		return
	}

	if msg.Message() != "" {
		fmt.Printf("\r                                               %s%s : %s%s%s\n>", red, pretty(msg), green, msg.Message(), blue)
	}

	for _, a := range msg.Attachments() {
		handleAttachment(msg.Source(), a)
	}

	// if no peer was specified on the command line, start a conversation with the first one contacting us
	if to == "" {
		to = msg.Source()
		isGroup := false
		if msg.Group() != "" {
			isGroup = true
			to = msg.Group()
		}
		go conversationLoop(isGroup)
	}
	go conversationLoop(false)
}

func handleAttachment(src string, b []byte) {
	f, err := ioutil.TempFile(".", "TextSecure_Attachment")
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("Saving attachment of length %d from %s to %s", len(b), src, f.Name())
	f.Write(b)

}

func pretty(msg *textsecure.Message) string {
	m := getName(msg.Source())
	if msg.Group() != "" {
		m = m + "[" + msg.Group() + "]"
	}
	return m
}

// getName returns the local contact name corresponding to a phone number,
// or failing to find a contact the phone number itself
func getName(tel string) string {
	if n, ok := telToName[tel]; ok {
		return n
	}
	return tel
}

var telToName map[string]string

func main() {
	flag.Parse()
	log.SetFlags(0)
	client := &textsecure.Client{
		RootDir:            ".",
		ReadLine:           textsecure.ConsoleReadLine,
		GetStoragePassword: getStoragePassword,
		MessageHandler:     messageHandler,
	}
	err := textsecure.Setup(client)
	if err != nil {
		log.Fatal(err)
	}

	if !echo {
		contacts, err := textsecure.GetRegisteredContacts()
		if err != nil {
			log.Printf("Could not get contacts: %s\n", err)
		}

		telToName = make(map[string]string)
		for _, c := range contacts {
			telToName[c.Tel] = c.Name
		}
	if fingerprint != "" {
		textsecure.ShowFingerprint(fingerprint)
		return
	}

		// If "to" matches a contact name then get its phone number, otherwise assume "to" is a phone number
		for _, c := range contacts {
			if strings.EqualFold(c.Name, to) {
				to = c.Tel
				break
			}
		}
		if to != "" {
			// Send attachment with optional message then exit
			if attachment != "" {
				err := textsecure.SendFileAttachment(to, message, attachment)
				if err != nil {
					log.Fatal(err)
				}
				return
			}
			// Send a message then exit
			if message != "" {
				err := textsecure.SendMessage(to, message)
				if err != nil {
					log.Fatal(err)
				}
				return
			}

			// Enter conversation mode
			go conversationLoop(false)
		}
	}

	err = textsecure.ListenForMessages()
	if err != nil {
		log.Println(err)
	}
}
