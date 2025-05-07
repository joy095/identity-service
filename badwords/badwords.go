package badwords

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/joy095/identity/logger"
)

// BadWordRequest represents a request to check text for bad words
type BadWordRequest struct {
	Text string `json:"text" binding:"required"`
}

// BadWordResponse represents the response from a bad word check
type BadWordResponse struct {
	ContainsBadWords bool `json:"containsBadWords"`
}

// badWords is a list of bad words or patterns loaded from a text file.
var badWords []string

// LoadBadWords loads bad words from a text file.
// Each line in the file represents a bad word or pattern.
func LoadBadWords(filename string) (bool, error) {
	logger.InfoLogger.Info("LoadBadWords called")

	data, err := os.ReadFile(filename)
	if err != nil {
		return false, err
	}

	// Split the file content into lines
	badWords = strings.Split(string(data), "\n")

	// Trim whitespace and remove empty lines
	for i := 0; i < len(badWords); i++ {
		badWords[i] = strings.TrimSpace(badWords[i])
		if badWords[i] == "" {
			badWords = slices.Delete(badWords, i, i+1)
			i-- // Adjust index after removing an empty line
		}
	}

	fmt.Printf("Loaded %d bad words from text file\n", len(badWords))
	return true, nil
}

// ContainsBadWords checks if the input text contains any bad words.
// It now checks if the exact word matches any word in the bad words list.
func ContainsBadWords(text string) bool {
	logger.InfoLogger.Info("ContainsBadWords called")
	// Convert input to lowercase and split into words
	words := strings.Fields(strings.ToLower(text))

	// Check each word against the bad words list
	for _, word := range words {
		// Remove any punctuation from the word
		word = strings.Trim(word, ".,!?;:\"'()[]{}")

		// Check if this word is in the bad words list
		for _, badWord := range badWords {
			if strings.ToLower(badWord) == word {
				logger.InfoLogger.Infof("Bad word detected: %s\n", word)
				fmt.Printf("Bad word detected: %s\n", word)
				return true
			}
		}
	}
	return false
}

// CheckText checks if the input text contains any bad words and returns a response.
func CheckText(text string) BadWordResponse {
	return BadWordResponse{
		ContainsBadWords: ContainsBadWords(text),
	}
}

// AddBadWord adds a new bad word to the list.
func AddBadWord(badWord string) (bool, error) {
	if badWord == "" {
		return false, errors.New("bad word must not be empty")
	}
	badWords = append(badWords, badWord)
	return true, nil
}

// RemoveBadWord removes a bad word from the list.
func RemoveBadWord(badWord string) bool {
	for i, bw := range badWords {
		if bw == badWord {
			badWords = slices.Delete(badWords, i, i+1)
			return true
		}
	}
	return false
}

// ListBadWords returns the current list of bad words.
func ListBadWords() []string {
	return badWords
}
