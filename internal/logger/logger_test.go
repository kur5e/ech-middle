package logger_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ech-middle/internal/config"
	"ech-middle/internal/logger"
)

func TestNewLogger_Stdout_Color(t *testing.T) {
	log := logger.NewLogger(config.LogConfig{
		Level: "debug",
		File:  "",
		Color: true,
	})
	if log == nil {
		t.Fatal("NewLogger returned nil")
	}
	log.Debugf("test debug message")
	log.Infof("test info message")
	log.Warnf("test warn message")
	log.Errorf("test error message")
}

func TestNewLogger_Stdout_NoColor(t *testing.T) {
	log := logger.NewLogger(config.LogConfig{
		Level: "info",
		File:  "",
		Color: false,
	})
	log.Infof("plain info message")
}

func TestNewLogger_FileOutput(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	log := logger.NewLogger(config.LogConfig{
		Level: "debug",
		File:  logPath,
		Color: true,
	})
	log.Infof("file test info")
	log.Debugf("file test debug")
	log.Warnf("file test warn")
	log.Errorf("file test error")
	log.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("cannot read log file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "file test info") {
		t.Error("log file missing info message")
	}
	if !strings.Contains(content, "file test error") {
		t.Error("log file missing error message")
	}
}

func TestLogger_LevelFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "level.log")

	// Only ERROR level.
	log := logger.NewLogger(config.LogConfig{
		Level: "error",
		File:  logPath,
		Color: false,
	})
	log.Debugf("should not appear")
	log.Infof("should not appear")
	log.Warnf("should not appear")
	log.Errorf("should appear")
	log.Close()

	data, _ := os.ReadFile(logPath)
	content := string(data)
	if strings.Contains(content, "should not appear") {
		t.Error("level filtering failed: low-level messages leaked")
	}
	if !strings.Contains(content, "should appear") {
		t.Error("level filtering failed: expected message missing")
	}
}

func TestLogger_WarnLevel(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "warn.log")

	log := logger.NewLogger(config.LogConfig{
		Level: "warn",
		File:  logPath,
		Color: false,
	})
	log.Debugf("debug msg")
	log.Infof("info msg")
	log.Warnf("warn msg")
	log.Errorf("error msg")
	log.Close()

	data, _ := os.ReadFile(logPath)
	content := string(data)
	if strings.Contains(content, "debug msg") || strings.Contains(content, "info msg") {
		t.Error("warn level should filter debug and info")
	}
	if !strings.Contains(content, "warn msg") || !strings.Contains(content, "error msg") {
		t.Error("warn level should include warn and error")
	}
}

func TestLogger_InvalidLevel_DefaultsToInfo(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "invalid-level.log")

	log := logger.NewLogger(config.LogConfig{
		Level: "invalid",
		File:  logPath,
		Color: false,
	})
	log.Infof("info with invalid level")
	log.Debugf("debug with invalid level")
	log.Close()

	data, _ := os.ReadFile(logPath)
	content := string(data)
	if !strings.Contains(content, "info with invalid level") {
		t.Error("invalid level should default to info, allow info messages")
	}
	if strings.Contains(content, "debug with invalid level") {
		t.Error("invalid level should default to info, filter debug messages")
	}
}

func TestLogger_FileOutput_DisablesColor(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "nocolor.log")

	log := logger.NewLogger(config.LogConfig{
		Level: "debug",
		File:  logPath,
		Color: true,
	})
	log.Infof("no color test")
	log.Close()

	data, _ := os.ReadFile(logPath)
	content := string(data)
	// ANSI escape sequences start with \033 or \x1b
	if strings.Contains(content, "\033[") {
		t.Error("color codes should be stripped in file output")
	}
}

func TestLogger_Concurrent(t *testing.T) {
	log := logger.NewLogger(config.LogConfig{
		Level: "debug",
		File:  "",
		Color: false,
	})

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				log.Debugf("goroutine %d: message %d", id, j)
				log.Infof("goroutine %d: info %d", id, j)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestLogger_EmptyFile(t *testing.T) {
	log := logger.NewLogger(config.LogConfig{
		Level: "info",
		File:  "",
		Color: true,
	})
	log.Infof("stdout test")
}
