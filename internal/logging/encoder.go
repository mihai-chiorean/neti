package logging

import (
	"go.uber.org/zap"
)

func getEncoderConfig() {
	_ = zap.NewProductionEncoderConfig()
}
