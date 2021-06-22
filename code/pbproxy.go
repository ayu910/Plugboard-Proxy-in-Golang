package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	//"crypto/sha1"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

var password string

func decrypt(password string, data []byte) ([]byte, error) {
	salt := []byte("abc1233")
	key := pbkdf2.Key([]byte(password), salt, 4096, 32, sha256.New)

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	fmt.Println("\nDecrypted Text : ", string(plaintext))
	return plaintext, nil
}

func encrypt(password string, data []byte) ([]byte, error) {

	salt := []byte("abc1233")
	key := pbkdf2.Key([]byte(password), salt, 4096, 32, sha256.New)

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	fmt.Println("\nEncrypted Text : ", string(ciphertext))
	return ciphertext, nil
}

func pipe(src, dst *net.TCPConn, decryptFlag bool) {
	buff := make([]byte, 0xffff)
	//fmt.Println("\nPipe initialized from ", src.RemoteAddr().(*net.TCPAddr).IP, "to", dst.RemoteAddr().(*net.TCPAddr).IP)
	for {
		// fmt.Println("Reading from ", src.RemoteAddr().(*net.TCPAddr).IP)
		n, err := src.Read(buff)
		// fmt.Println(string(buff))
		if err != nil {
			if err != io.EOF {
				fmt.Printf("Read failed '%s'\n", err)
			}
			return
		}
		//fmt.Println("Text read from", src.RemoteAddr().(*net.TCPAddr).IP, "->", string(buff[:n]))

		b := buff[:n]

		if decryptFlag {
			b, err := decrypt(string(password), b)
			checkError(err, "Error while decryption")
			b = []byte(string(b) + "\n")
			//fmt.Println("\nText decrypted", string(b))

			fmt.Println("\nWriting to service ")
			n, err = dst.Write(b)
			if err != nil {
				fmt.Printf("Write failed '%s'\n", err)
				return
			}
		} else {
			fmt.Println("\nWriting back to client")

			n, err = dst.Write(b)
			if err != nil {
				fmt.Printf("Write failed '%s'\n", err)
				return
			}
		}
	}
}

func getRemoteConnection(remoteAddr *net.TCPAddr) *net.TCPConn {
	remoteConnection, err := net.DialTCP("tcp", nil, remoteAddr)
	checkError(err, "Failed to establish connection to redirection port")

	return remoteConnection
}

func start2WayCommunication(listenerAddr, redirectAddr *net.TCPAddr, clientConnection *net.TCPConn) {
	remoteConnection := getRemoteConnection(redirectAddr)

	// TODO: client to remote - here you need to decrypt message from client and send to server
	go pipe(clientConnection, remoteConnection, true)
	go pipe(remoteConnection, clientConnection, false) // remote back to client
}

func main() {
	// flag.Parse()
	listeningPort := flag.String("l", "", "listening port")
	passwordFile := flag.String("p", "", "Password file (Required)")
	dstHost := ""
	dstPort := ""
	flag.Parse()

	if *passwordFile == "" {
		fmt.Println("./pbproxy -l 5000 -p pass.txt google.com 4567")
		flag.PrintDefaults()
		os.Exit(1)
	}

	argsArr := flag.Args()
	if len(argsArr) == 2 {
		dstHost = argsArr[0]
		dstPort = argsArr[1]
	} else {
		fmt.Println("./pbproxy -l 5000 -p pass.txt google.com 4567")
		fmt.Println("Destination host and port are required arguments")
		flag.PrintDefaults()
		os.Exit(1)
	}

	pass, err := ioutil.ReadFile(*passwordFile)
	checkError(err, "Error reading password file")
	fmt.Print("\nPassword is ", string(pass))
	password = string(pass)

	if *listeningPort == "" { // CLIENT MODE
		fmt.Println("\nStarted in client mode")
		fmt.Println("\nPassword file", *passwordFile, "and connecting to", dstHost+":"+dstPort)

		remoteAddrStr := dstHost + ":" + dstPort

		dstAddr, err := net.ResolveTCPAddr("tcp", remoteAddrStr)
		checkError(err, "Failed to resolve redirection address "+remoteAddrStr)
		remoteConnection := getRemoteConnection(dstAddr)

		for {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Enter text : ")
			text, _ := reader.ReadString('\n')

			// TODO:call encrypter below
			ciphertext, err := encrypt(password, []byte(text))
			// ciphertext : =[]byte(text)
			checkError(err, "Error while encryption")
			remoteConnection.Write(ciphertext)
			// TODO ENDS
			//fmt.Fprintf(remoteConnection, text)

			buff := make([]byte, 0xffff)
			responseLen, err := remoteConnection.Read(buff)
			checkError(err, "Error while reading response")
			// message, _ := bufio.NewReader(remoteConnection).ReadString()
			response := buff[:responseLen]
			fmt.Print("\nResponse recieved from server :", string(response))
		}
	} else { // REVERSE PROXY MODE
		fmt.Println("\nStarted in reverse proxy mode")
		fmt.Println("\nListening on localhost:"+*listeningPort, "with password file", *passwordFile, "and redirecting to", dstHost+":"+dstPort)

		listenAddrStr := "localhost:" + *listeningPort
		redirectAddrStr := dstHost + ":" + dstPort

		listenerAddr, err := net.ResolveTCPAddr("tcp", listenAddrStr)
		checkError(err, "Failed to resolve listener address "+listenAddrStr)

		redirectAddr, err := net.ResolveTCPAddr("tcp", redirectAddrStr)
		checkError(err, "Failed to resolve redirection address "+redirectAddrStr)

		listener, err := net.ListenTCP("tcp", listenerAddr)
		checkError(err, "Failed to start listener")

		for {
			clientConnection, err := listener.AcceptTCP()
			checkError(err, "Failed to establish connection with client")

			start2WayCommunication(listenerAddr, redirectAddr, clientConnection)
		}
	}
}

func checkError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
