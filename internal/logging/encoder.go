package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func getEncoderConfig() {
	config := zap.NewProductionEncoderConfig()
	zapcore.NewJSONEncoder
}
