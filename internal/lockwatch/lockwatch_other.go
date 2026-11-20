//go:build !linux && !darwin

package lockwatch

import "context"

func watch(context.Context) (<-chan string, error) { return nil, ErrUnsupported }
