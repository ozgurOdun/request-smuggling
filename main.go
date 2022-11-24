package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const crlf = "\r\n"

type Payloads struct {
	Permute   []PayloadType   `json: "permute"`
	Detection []DetectionType `json: "detection"`
}

type DetectionType struct {
	Type          string `json: "type"`
	Payload       string `json: "payload"`
	Contentlength int    `json: "content_length"`
}

type PayloadType struct {
	Type             string               `json: "type"`
	Contentlengthkey string               `json: "content_length_key"`
	Transferencoding TransferEncodingType `json: "transfer_encoding"`
}

type TransferEncodingType struct {
	Tekey   string `json: "te_key"`
	Tevalue string `json: "te_value"`
}

func preparePayload(method string, host string, payload PayloadType, detection DetectionType) string {
	headers := method + " / HTTP/1.1" + crlf + "Host: " + host + crlf
	headers = headers + payload.Contentlengthkey + strconv.Itoa(detection.Contentlength) + crlf
	headers = headers + payload.Transferencoding.Tekey + payload.Transferencoding.Tevalue + crlf
	smugglePayload := headers + detection.Payload
	return smugglePayload
}

func test(targetUrl string, method string, payload PayloadType, detection DetectionType, timeout int) {
	parsedUrl, _ := url.Parse(targetUrl)
	smugglePayload := preparePayload(method, parsedUrl.Host, payload, detection)
	start := time.Now()
	conn, err := net.Dial("tcp", parsedUrl.Host+":"+parsedUrl.Scheme)
	if err != nil {
		fmt.Println("connection error: ", err)
		os.Exit(1)
	}

	fmt.Fprintf(conn, smugglePayload)
	elapsed := time.Since(start)
	responseFirstLine, err := bufio.NewReader(conn).ReadString('\n')
	status := strings.Split(responseFirstLine, " ")
	var msg string
	if elapsed > time.Duration(timeout*10e8) {
		msg = "Possible HTTP Request Smuggling"
	} else {
		msg = "OK"
	}
	fmt.Println(payload.Type, detection.Type, parsedUrl.Host, status[1], elapsed.Seconds(), msg)
    if elapsed > time.Duration(timeout*10e8) {
        //verify the vulnerability here
    }
}

func parsePayloads() Payloads {
	payloadsFile, _ := ioutil.ReadFile("payloads.json")
	payloads := Payloads{}

	err := json.Unmarshal([]byte(payloadsFile), &payloads)
	if err != nil {
		fmt.Println("Error parsing payloads", err)
		os.Exit(1)
	}
	return payloads
}

func main() {
    //flag definitions
	targetUrl := flag.String("u", "http://example.com", "url")
	timeout := flag.Int("t", 10, "timeout in sec - default 10 - max 60")
	retry := flag.Int("r", 2, "retry count - default 2 - max 10")
	method := flag.String("m", "POST", "method - GET or POST - default POST")
	flag.Parse()
	fmt.Println("url : ", *targetUrl)
	fmt.Println("timeout : ", *timeout)
	fmt.Println("retry : ", *retry)
	fmt.Println("method : ", *method)

    //flag validation
	urlRegex := `(https?:\/\/)([\w\-])+\.{1}([a-zA-Z]{2,63})([\/\w-]*)*\/?\??([^#\n\r]*)?#?([^\n\r]*)`
	methodRegex := `^GET|POST$`
	urlFormatOk, err := regexp.Match(urlRegex, []byte(*targetUrl))
	methodFormatOk, err1 := regexp.Match(methodRegex, []byte(*method))
	if err != nil || err1 != nil {
		fmt.Println("Url Regex Error", err)
		os.Exit(1)
	}
	if !urlFormatOk || !methodFormatOk || *timeout > 60 || *retry > 10 {
		fmt.Println("Url or method format is wrong. Usage:")
		flag.PrintDefaults()
		os.Exit(1)
	} else {
		fmt.Println("Url format is OK.", urlFormatOk)
		fmt.Println("Method format is OK.", methodFormatOk)
        fmt.Println("Timeout and retry count is OK.", *timeout, *retry)
	}

	payloads := parsePayloads()

    //start attack
	for i := 0; i < len(payloads.Detection); i++ {
		for j := 0; j < len(payloads.Permute); j++ {
			test(*targetUrl, *method, payloads.Permute[j], payloads.Detection[i], *timeout)
		}
	}

}
