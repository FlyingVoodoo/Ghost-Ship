package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type TelegramMessage struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

func SendTelegramMessage(botToken, chatID, message string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)

	msg := TelegramMessage{
		ChatID:    chatID,
		Text:      message,
		ParseMode: "Markdown",
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("telegram request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

func SendTelegramAlert(botToken, chatID string, level, title, description string) error {
	levelPrefix := map[string]string{
		"CRITICAL": "[CRITICAL]",
		"WARNING":  "[WARNING]",
		"INFO":     "[INFO]",
		"SUCCESS":  "[PASS]",
	}

	message := fmt.Sprintf("%s %s\n", levelPrefix[level], title)
	message += fmt.Sprintf("\n%s\n", description)

	return SendTelegramMessage(botToken, chatID, message)
}
