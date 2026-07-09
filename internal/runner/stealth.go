package runner

import (
	"math/rand"
	"strings"
	"time"
)

var stealthRand = rand.New(rand.NewSource(time.Now().UnixNano()))

var stealthUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
}

func randomUserAgent() string {
	return stealthUserAgents[stealthRand.Intn(len(stealthUserAgents))]
}

func jitterValue(base, minPct, maxPct int) int {
	if base <= 0 {
		return base
	}
	low := float64(base) * (1.0 + float64(minPct)/100.0)
	high := float64(base) * (1.0 + float64(maxPct)/100.0)
	return int(low + stealthRand.Float64()*(high-low))
}

var browserHeaders = []string{
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
	"Accept-Language: en-US,en;q=0.9",
	"Sec-Ch-Ua-Mobile: ?0",
	"Sec-Fetch-Dest: document",
	"Sec-Fetch-Mode: navigate",
	"Sec-Fetch-Site: none",
	"Sec-Fetch-User: ?1",
	"Upgrade-Insecure-Requests: 1",
}

func applyStealthHeaders(options *Options) {
	ua := randomUserAgent()
	allHeaders := append([]string{"User-Agent: " + ua}, options.Headers...)
	allHeaders = append(allHeaders, browserHeaders...)
	options.Headers = allHeaders
}

func applyAggressiveJitter(options *Options) {
	if options.Concurrency > 0 {
		options.Concurrency = jitterValue(options.Concurrency, -15, 15)
	}
	if options.RateLimit > 0 {
		options.RateLimit = jitterValue(options.RateLimit, -10, 10)
	}
}

func isAggressiveProfile(options *Options) bool {
	return (options.Concurrency > 0 && options.Concurrency > 150) ||
		(options.RateLimit > 0 && options.RateLimit > 500) ||
		options.EnableDAST ||
		options.EnableHeadless
}

func buildStealthArgs(nucleiPath, target string, allowedSeverities []string, options Options) []string {
	applyStealthHeaders(&options)

	if isAggressiveProfile(&options) {
		applyAggressiveJitter(&options)
	}

	args := buildNucleiArgs(nucleiPath, target, allowedSeverities, options)

	if isAggressiveProfile(&options) {
		// ponytail: keep jitter at the numeric flag layer only; add debug-only delay metadata later if a traced command view is introduced.
	}

	return args
}

func hasNucleiFingerprint(args []string) bool {
	for _, arg := range args {
		if strings.Contains(strings.ToLower(arg), "nuclei") {
			return true
		}
	}
	return false
}
