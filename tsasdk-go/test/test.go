package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/tsasdk/tsasdk-go/crypto/digest"
	"github.com/tsasdk/tsasdk-go/tsp"
	"log"
	"os"
)

func main() {

	fmt.Println("start CreateRequest...")
	//create timestamprequest
	req, err := tsp.CreateRequest(digest.FromString("hello tsa"))
	if err != nil {
		log.Fatal(err)
	}
	req.CertReq = true
	fmt.Println("start GetHttp...")
	//get timestamp   server:unitrust timestamp server（rfc3161）
	ts := tsp.GetHttp(nil, "http://test1.tsa.cn/tsa", "tsademo", "tsademo")
	resp, err := ts.Timestamp(context.Background(), req)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("status:", resp.Status.Status)
	//get timestamptoken
	token, err := resp.SignedToken()
	if err != nil {
		log.Fatal(err)
	}
	//timestamptoken write disk
	filePath := "/go.tsa"
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("open file error", err)
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	write.Write(resp.TokenBytes())
	write.Flush()
	//get tstinfo
	info, err := token.Info()
	if err != nil {
		log.Fatal(err)
	}
	//print time
	fmt.Println("time:", info.GenTime)
	//print hash
	fmt.Println("hash:", hex.EncodeToString(info.MessageImprint.HashedMessage))

}
