package logging

import (
	"go.uber.org/zap"
)

func getEncoderConfig() {
	config := zap.NewProductionEncoderConfig()
}
