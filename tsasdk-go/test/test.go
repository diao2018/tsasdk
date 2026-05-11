package main

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/diao2018/tsasdk/tsasdk-go/crypto/digest"
	"github.com/diao2018/tsasdk/tsasdk-go/tsp"
)

func main() {
	ts := tsp.GetHttp(nil, "http://test1.tsa.cn/tsa", "tsademo", "tsademo")

	// === SHA-256 Test ===
	fmt.Println("========== SHA-256 Test ==========")
	req, err := tsp.CreateRequest(digest.FromString("hello tsa"))
	if err != nil {
		fmt.Println("SHA-256 CreateRequest ERROR:", err)
		return
	}
	req.CertReq = true
	resp, err := ts.Timestamp(context.Background(), req)
	if err != nil {
		fmt.Println("SHA-256 Timestamp ERROR:", err)
		return
	}
	fmt.Println("SHA-256 Status:", resp.Status.Status)
	token, err := resp.SignedToken()
	if err != nil {
		fmt.Println("SHA-256 SignedToken ERROR:", err)
		return
	}
	info, err := token.Info()
	if err != nil {
		fmt.Println("SHA-256 Info ERROR:", err)
		return
	}
	fmt.Println("SHA-256 Timestamp:", info.GenTime)
	fmt.Println("SHA-256 Hash:", hex.EncodeToString(info.MessageImprint.HashedMessage))

	// === SM3 Hash Test ===
	fmt.Println("\n========== SM3 Hash Test ==========")
	sm3Digest := digest.SM3.FromString("hello tsa sm3")
	fmt.Println("SM3 Digest:", sm3Digest)

	sm3Hash, err := digest.ComputeHashByAlgorithm(digest.SM3, []byte("hello tsa sm3"))
	if err != nil {
		fmt.Println("SM3 ComputeHash ERROR:", err)
		return
	}
	fmt.Println("SM3 Hash (hex):", hex.EncodeToString(sm3Hash))

	// SM3 timestamp request (may fail if TSA doesn't support SM3)
	sm3Req, err := tsp.CreateRequest(sm3Digest)
	if err != nil {
		fmt.Println("SM3 CreateRequest ERROR:", err)
		return
	}
	sm3Req.CertReq = true
	sm3Resp, err := ts.Timestamp(context.Background(), sm3Req)
	if err != nil {
		fmt.Println("SM3 Timestamp ERROR (server may not support SM3):", err)
	} else {
		fmt.Println("SM3 Status:", sm3Resp.Status.Status)
		sm3Token, _ := sm3Resp.SignedToken()
		if sm3Token != nil {
			sm3Info, _ := sm3Token.Info()
			if sm3Info != nil {
				fmt.Println("SM3 Timestamp:", sm3Info.GenTime)
			}
		}
	}

	fmt.Println("\n========== ALL TESTS COMPLETED ==========")
}
