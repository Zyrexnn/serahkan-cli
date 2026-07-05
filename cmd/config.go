package cmd

import (
	"fmt"
	"strconv"
	"strings"

	cfgstore "github.com/Zyrexnn/serahkan-cli/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage persisted CLI configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		endpoint, _ := cmd.Flags().GetString("endpoint")
		model, _ := cmd.Flags().GetString("model")

		if endpoint == "" && model == "" {
			return cmd.Help()
		}

		existing := cfgstore.LoadScanConfig()

		if endpoint != "" {
			existing.AIEndpoint = endpoint
		}
		if model != "" {
			existing.AIModel = model
		}

		path, err := cfgstore.SaveScanConfig(existing)
		if err != nil {
			return err
		}

		fmt.Fprintf(out, "saved to %s\n", path)
		if endpoint != "" {
			fmt.Fprintf(out, "ai-endpoint: %s\n", endpoint)
		}
		if model != "" {
			fmt.Fprintf(out, "ai-model: %s\n", model)
		}
		return nil
	},
}

var configViewCmd = &cobra.Command{
	Use:   "view",
	Short: "Print the active config file contents",
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()

		cfg, path, err := cfgstore.Load()
		if err != nil {
			return err
		}

		fmt.Fprintf(out, "path: %s\n", path)
		fmt.Fprintf(out, "ai.endpoint: %s\n", blankIfEmpty(cfg.AI.Endpoint))
		fmt.Fprintf(out, "ai.model: %s\n", blankIfEmpty(cfg.AI.Model))
		fmt.Fprintf(out, "ai.api_key: %s\n", maskSecret(cfg.AI.APIKey))
		fmt.Fprintf(out, "ai.timeout_seconds: %s\n", intIfSet(cfg.AI.TimeoutSeconds))
		fmt.Fprintf(out, "ai.retry_count: %s\n", intIfSet(cfg.AI.RetryCount))

		return nil
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a persisted config value",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _, err := cfgstore.Load()
		if err != nil {
			return err
		}

		key := strings.ToLower(strings.TrimSpace(args[0]))
		value := strings.TrimSpace(args[1])

		switch key {
		case "ai.endpoint":
			cfg.AI.Endpoint = value
		case "ai.model":
			cfg.AI.Model = value
		case "ai.api_key":
			cfg.AI.APIKey = value
		case "ai.timeout_seconds":
			parsed, err := parseNonNegativeInt(value)
			if err != nil {
				return err
			}
			cfg.AI.TimeoutSeconds = parsed
		case "ai.retry_count":
			parsed, err := parseNonNegativeInt(value)
			if err != nil {
				return err
			}
			cfg.AI.RetryCount = parsed
		default:
			return fmt.Errorf("unsupported config key %q", key)
		}

		path, err := cfgstore.Save(cfg)
		if err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "saved %s to %s\n", key, path)
		return nil
	},
}

var configUnsetCmd = &cobra.Command{
	Use:   "unset <key>",
	Short: "Unset a persisted config value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _, err := cfgstore.Load()
		if err != nil {
			return err
		}

		key := strings.ToLower(strings.TrimSpace(args[0]))

		switch key {
		case "ai.endpoint":
			cfg.AI.Endpoint = ""
		case "ai.model":
			cfg.AI.Model = ""
		case "ai.api_key":
			cfg.AI.APIKey = ""
		case "ai.timeout_seconds":
			cfg.AI.TimeoutSeconds = 0
		case "ai.retry_count":
			cfg.AI.RetryCount = 0
		default:
			return fmt.Errorf("unsupported config key %q", key)
		}

		path, err := cfgstore.Save(cfg)
		if err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "unset %s in %s\n", key, path)
		return nil
	},
}

func init() {
	configCmd.Flags().String("endpoint", "", "AI endpoint URL to persist in config.yaml")
	configCmd.Flags().String("model", "", "AI model name to persist in config.yaml")
	configCmd.AddCommand(configViewCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configUnsetCmd)
	rootCmd.AddCommand(configCmd)
}

func blankIfEmpty(value string) string {
	if strings.TrimSpace(value) == "" {
		return "(empty)"
	}

	return value
}

func maskSecret(value string) string {
	if strings.TrimSpace(value) == "" {
		return "(empty)"
	}

	if len(value) <= 4 {
		return "****"
	}

	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}

func intIfSet(value int) string {
	if value <= 0 {
		return "(empty)"
	}

	return fmt.Sprintf("%d", value)
}

func parseNonNegativeInt(value string) (int, error) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("invalid integer value %q", value)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("value must be non-negative")
	}

	return parsed, nil
}
