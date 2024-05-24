package logger

import (
	"os"

	conf "projectsphere/beli-mang/config"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func setConsoleLogger() (zapcore.Core, []zap.Option) {
	writer := zapcore.AddSync(os.Stdout)

	config := zap.NewDevelopmentEncoderConfig()
	config.EncodeLevel = zapcore.CapitalColorLevelEncoder

	encoder := zapcore.NewConsoleEncoder(config)

	logLevel := zap.NewAtomicLevelAt(zap.WarnLevel)

	if conf.GetString("DEBUG_MODE") == "true" {
		logLevel = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	options := append([]zap.Option{}, zap.Development(), zap.AddCaller(), zap.AddStacktrace(zap.DPanicLevel))

	return zapcore.NewCore(encoder, writer, logLevel), options
}
