package main

import (
	"fmt"
	"testing"
	"time"
)

func TestGenId(t *testing.T) {
	for i := 0; i < 10; i++ {
		fmt.Printf("%s\n", genId())
		time.Sleep(0 * time.Millisecond)
	}
}
