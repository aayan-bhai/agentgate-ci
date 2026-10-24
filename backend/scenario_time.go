package main

import "time"

func nowTimestamp() string {
	return time.Now().Format("15:04:05")
}
