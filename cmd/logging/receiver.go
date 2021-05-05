package logging

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type fields map[string]interface{}

//type caller struct {
//	File string
//	Line int
//}

type caller string

// Line -
func (c *caller) Line() int {

	s := string(*c)
	pieces := strings.Split(s, ":")

	if len(pieces) > 1 {
		line, err := strconv.Atoi(pieces[1])
		if err != nil {
			return 0
		}
		return line
	}
	return 0
}

// File -
func (c *caller) File() string {

	s := string(*c)
	pieces := strings.Split(s, ":")
	if len(pieces) > 0 {
		return pieces[0]
	}
	return ""
}

//func (c *caller) UnmarshalJSON(b []byte) error {
//	var raw string
//	if err := json.Unmarshal(b, &raw); err != nil {
//		return err
//	}
//
//	pieces := strings.Split(raw, ":")
//	c.File = pieces[0]
//	if len(pieces) > 1 {
//		line, err := strconv.Atoi(pieces[1])
//		if err != nil {
//			return err
//		}
//		c.Line = line
//	}
//	return nil
//}

type entry struct {
	fields
	Level      string `json:"level"`
	Ts         string //time.Time `json:"ts"`
	LoggerName string
	Msg        string `json:"msg"`
	Defined    bool
	Caller     caller `json:"caller"`
	Function   string
	Stack      string
}

func (e *entry) UnmarshalJSON(input []byte) error {
	// unmarshal json to a map
	foomap := make(map[string]interface{})
	json.Unmarshal(input, &foomap)

	// create a mapstructure decoder
	var md mapstructure.Metadata
	decoder, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			Metadata: &md,
			Result:   e,
		})
	if err != nil {
		return err
	}

	// decode the unmarshalled map into the given struct
	if err := decoder.Decode(foomap); err != nil {
		return err
	}

	// copy and return unused fields
	//unused := map[string]interface{}{}
	e.fields = fields(map[string]interface{}{})
	for _, k := range md.Unused {
		e.fields[k] = foomap[k]
	}
	return nil
}

func (e *entry) zapEntry() zapcore.Entry {
	ti, err := time.Parse("2006-01-02T15:04:05.000Z0700", e.Ts)
	if err != nil {
		return zapcore.Entry{}
	}
	ze := zapcore.Entry{
		Level: func() zapcore.Level {
			switch e.Level {
			case "debug":
				return zapcore.DebugLevel
			case "info":
				return zapcore.InfoLevel
			case "warn":
				return zapcore.WarnLevel
			case "error":
				return zapcore.ErrorLevel
			case "fatal":
				return zapcore.FatalLevel
			}
			return zapcore.PanicLevel
		}(),
		Time:       ti,
		LoggerName: e.LoggerName,
		Message:    e.Msg,
		Stack:      e.Stack,
		Caller: zapcore.EntryCaller{
			File:     e.Caller.File(),
			Function: e.Function,
			Defined:  true,
			Line:     e.Caller.Line(),
		},
	}
	return ze
}

// Receiver -
type Receiver struct {
	L *zap.SugaredLogger
}

// Decode -
func (r *Receiver) Decode(in io.Reader) {

	rawEntry := json.NewDecoder(in)
	for {
		var e entry
		if err := rawEntry.Decode(&e); err == io.EOF {
			r.L.Error(err)
			break
		} else if err != nil {
			r.L.Error(err)
		}
		ze := e.zapEntry()
		args := []interface{}{}
		for k, v := range e.fields {
			args = append(args, k, v)
		}
		fields, _ := sweetenFields(args)
		if err := r.L.Desugar().Core().Write(ze, fields); err != nil {
			r.L.Named("GATEWAY+LOG_RECEIVER").Errorw("Failed to output log", "error", err)
		}
	}
}

func (r *Receiver) log(raw []byte) {
	var e entry
	if err := json.Unmarshal(raw, &e); err != nil {
		r.L.Error("Failed to parse log", "error", err)
	}
	//fmt.Printf("%+v\n", e)
	ze := e.zapEntry()
	args := []interface{}{}
	for k, v := range e.fields {
		args = append(args, k, v)
	}
	fields, _ := sweetenFields(args)
	if err := r.L.Desugar().Core().Write(ze, fields); err != nil {
		r.L.Named("GATEWAY+LOG_RECEIVER").Errorw("Failed to output log", "error", err)
	}
}

func sweetenFields(args []interface{}) ([]zap.Field, error) {
	if len(args) == 0 {
		return nil, nil
	}

	// Allocate enough space for the worst case; if users pass only structured
	// fields, we shouldn't penalize them with extra allocations.
	fields := make([]zap.Field, 0, len(args))
	var invalid invalidPairs

	for i := 0; i < len(args); {
		// This is a strongly-typed field. Consume it and move on.
		if f, ok := args[i].(zap.Field); ok {
			fields = append(fields, f)
			i++
			continue
		}

		// Make sure this element isn't a dangling key.
		if i == len(args)-1 {
			//s.base.DPanic(_oddNumberErrMsg, Any("ignored", args[i]))
			break
		}

		// Consume this value and the next, treating them as a key-value pair. If the
		// key isn't a string, add this pair to the slice of invalid pairs.
		key, val := args[i], args[i+1]
		if keyStr, ok := key.(string); !ok {
			// Subsequent errors are likely, so allocate once up front.
			if cap(invalid) == 0 {
				invalid = make(invalidPairs, 0, len(args)/2)
			}
			invalid = append(invalid, invalidPair{i, key, val})
		} else {
			fields = append(fields, zap.Any(keyStr, val))
		}
		i += 2
	}

	// If we encountered any invalid key-value pairs, log an error.
	if len(invalid) > 0 {
		//s.base.DPanic(_nonStringKeyErrMsg, zap.Array("invalid", invalid))
	}
	return fields, nil
}

type invalidPair struct {
	position   int
	key, value interface{}
}

func (p invalidPair) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddInt64("position", int64(p.position))
	zap.Any("key", p.key).AddTo(enc)
	zap.Any("value", p.value).AddTo(enc)
	return nil
}

type invalidPairs []invalidPair

func (ps invalidPairs) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	var err error
	for i := range ps {
		err = multierr.Append(err, enc.AppendObject(ps[i]))
	}
	return err
}
