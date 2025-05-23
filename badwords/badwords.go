package badwords

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync" // For thread-safe access to badWordsMap

	"github.com/joy095/identity/logger" // Assuming this logger is available
)

// BadWordRequest represents a request to check text for bad words
type BadWordRequest struct {
	Text string `json:"text" binding:"required"`
}

// BadWordResponse represents the response from a bad word check
type BadWordResponse struct {
	ContainsBadWords bool `json:"containsBadWords"`
}

// badWordsMap is a set of bad words for efficient lookups.
// Using a map[string]struct{} is an efficient way to implement a set in Go.
var badWordsMap map[string]struct{}

// mutex to protect concurrent access to badWordsMap
var mu sync.RWMutex

// LoadBadWords loads bad words from a text file into a map for fast lookups.
// Each line in the file represents a bad word or pattern.
func LoadBadWords(filename string) error {
	logger.InfoLogger.Info("LoadBadWords called")

	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read bad words file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	newBadWordsMap := make(map[string]struct{})

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" {
			newBadWordsMap[strings.ToLower(trimmedLine)] = struct{}{} // Store in lowercase for case-insensitive matching
		}
	}

	mu.Lock()
	badWordsMap = newBadWordsMap
	mu.Unlock()

	fmt.Printf("Loaded %d bad words from text file\n", len(badWordsMap))
	return nil
}

// ContainsBadWords checks if the input text contains any bad words using the map for efficient lookups.
func ContainsBadWords(text string) bool {
	logger.InfoLogger.Info("ContainsBadWords called")

	if badWordsMap == nil || len(badWordsMap) == 0 {
		logger.InfoLogger.Warn("Bad words list is empty or not loaded.")
		return false // No bad words to check against
	}

	// Convert input to lowercase and split into words
	// Using FieldsFunc to handle various delimiters including newlines, tabs, etc.
	words := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !('a' <= r && r <= 'z' || '0' <= r && r <= '9') // Split on anything that's not a letter or number
	})

	mu.RLock() // Use RLock for read-only access
	defer mu.RUnlock()

	// Check each word against the bad words map
	for _, word := range words {
		// No need to trim punctuation explicitly if FieldsFunc handles it well.
		// If you only want to remove leading/trailing punctuation, keep the Trim.
		// For example, "hello." would become "hello"
		// word = strings.Trim(word, ".,!?;:\"'()[]{}")

		if _, found := badWordsMap[word]; found {
			logger.InfoLogger.Infof("Bad word detected: %s\n", word)
			fmt.Printf("Bad word detected: %s\n", word)
			return true
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
func AddBadWord(badWord string) error {
	if badWord == "" {
		return errors.New("bad word must not be empty")
	}

	mu.Lock()
	defer mu.Unlock()

	if badWordsMap == nil {
		badWordsMap = make(map[string]struct{})
	}
	badWordsMap[strings.ToLower(badWord)] = struct{}{}
	logger.InfoLogger.Infof("Added bad word: %s", badWord)
	return nil
}

// RemoveBadWord removes a bad word from the list.
func RemoveBadWord(badWord string) bool {
	mu.Lock()
	defer mu.Unlock()

	if badWordsMap == nil {
		return false
	}

	// Ensure we are removing the lowercase version
	badWordLower := strings.ToLower(badWord)
	if _, found := badWordsMap[badWordLower]; found {
		delete(badWordsMap, badWordLower)
		logger.InfoLogger.Infof("Removed bad word: %s", badWord)
		return true
	}
	return false
}

// ListBadWords returns the current list of bad words (as a slice for convenience).
func ListBadWords() []string {
	mu.RLock()
	defer mu.RUnlock()

	words := make([]string, 0, len(badWordsMap))
	for word := range badWordsMap {
		words = append(words, word)
	}
	return words
}
