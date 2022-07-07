package tsp

import (
	"context"
)

type Timestamper interface {
	Timestamp(context.Context, *Request) (*Response, error)
}
