package main

import (
	"auth/internal/handler"
	"auth/internal/service"
	"fmt"
)

func main() {
	fmt.Println("START APPLICATION")

	handler.New(service.NewJWTService()).Run()
}
