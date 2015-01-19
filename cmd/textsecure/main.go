package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"github.com/zmanian/textsecure"
	"golang.org/x/crypto/ssh/terminal"
	"github.com/jessevdk/go-flags"
)

// Simple command line test app for TextSecure.
// It can act as an echo service, send one-off messages and attachments,
// or carry on a conversation with another client

type Session struct {
	to string
}

type Sessions []Session


var sessions Sessions
var activeSession *Session

func findSession(sessions Sessions, recipient string) (int, error) {
	for index, sess := range sessions {
		if sess.to == recipient {
			return index, nil
		}
	}
	return -1, fmt.Errorf("Session not found")
}

type Options struct {
	Echo bool `short:"e" long:"echo" description:"Act as an echo service" default:"false"`

	To string `short:"t" long:"to" description:"Contact name to send the message to" default:"" `

	Group bool `short:"g" long:"group" description:"Destination is a group" default:"false"`

  Message string `short:"m" long:"message" description:"Single message to send, then exit" default:""`
  
  Attachment string `short:"a" long:"attachment" description:"File to attach" default:""`
  
  Fingerprint string `short:"f" long:"fingerprint" description:"Name of contact to get identity key fingerprint" default:""`
}


var options Options
var	parser = flags.NewParser(&options, flags.Default)


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
			err = textsecure.SendGroupMessage(activeSession.to, message)
		} else {
			err = textsecure.SendMessage(activeSession.to, message)
		}
		if err != nil {
			log.Println(err)
		}
	}
}

func messageHandler(msg *textsecure.Message) {
	if options.Echo {
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
	if options.To == "" {
	  
	  i, err := findSession(sessions, msg.Source())
	  if err != nil {
	    sessions = append(sessions, Session{to: msg.Source()})
		  activeSession = &sessions[len(sessions)-1]
	  }else {
		  activeSession = &sessions[i]
	  }
	  
		isGroup := false
		if msg.Group() != "" {
			isGroup = true
			options.To = msg.Group()
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
  
	log.SetFlags(0)


  if _, err := parser.Parse(); err != nil {
    log.Fatal(err)
	}

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

	if !options.Echo {
		contacts, err := textsecure.GetRegisteredContacts()
		if err != nil {
			log.Printf("Could not get contacts: %s\n", err)
		}

		telToName = make(map[string]string)
		for _, c := range contacts {
			telToName[c.Tel] = c.Name
		}
	if options.Fingerprint != "" {
		textsecure.ShowFingerprint(options.Fingerprint)
		return
	}

		// If "to" matches a contact name then get its phone number, otherwise assume "to" is a phone number
		for _, c := range contacts {
			if strings.EqualFold(c.Name, options.To) {
				options.To = c.Tel
				break
			}
		}
		if options.To != "" {
			// Send attachment with optional message then exit
			if options.Attachment != "" {
				err := textsecure.SendFileAttachment(options.To, options.Message, options.Attachment)
				if err != nil {
					log.Fatal(err)
				}
				return
			}
			// Send a message then exit
			if options.Message != "" {
				err := textsecure.SendMessage(options.To, options.Message)
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
