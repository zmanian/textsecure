package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/zmanian/textsecure"
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
	sessions      Sessions
	activeSession *Session
)

func init() {
	flag.BoolVar(&echo, "echo", false, "Act as an echo service")
	flag.StringVar(&to, "to", "", "Contact name to send the message to")
	flag.StringVar(&to, "t", "", "Contact name to send the message to")
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

// conversationLoop sends messages read from the console
func conversationLoop() {
	for {
		message := textsecure.ConsoleReadLine(fmt.Sprintf("%s%s>", blue, activeSession.to))
		if message == "" {
			continue
		}
		err := textsecure.SendMessage(activeSession.to, message)
		if err != nil {
			log.Println(err)
		}
	}
}

func messageHandler(msg *textsecure.Message) {
	if echo {
		err := textsecure.SendMessage(msg.Source(), msg.Message())
		if err != nil {
			log.Println(err)
		}
		return
	}

	if msg.Message() != "" {
		fmt.Printf("\r                                               %s%s : %s%s%s\n>", red, getName(msg.Source()), green, msg.Message(), blue)
	}

	for _, a := range msg.Attachments() {
		handleAttachment(msg.Source(), a)
	}

	// if no peer was specified on the command line, start a conversation with the first one contacting us
	if to == "" {
		to = msg.Source()
		go conversationLoop()
	}
	go conversationLoop()
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
		RootDir:        ".",
		ReadLine:       textsecure.ConsoleReadLine,
		MessageHandler: messageHandler,
	}
	textsecure.Setup(client)

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
			go conversationLoop()
		}
	}

	err := textsecure.ListenForMessages()
	if err != nil {
		log.Println(err)
	}
}
