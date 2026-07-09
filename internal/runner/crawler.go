package runner

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
)

type CrawlResult struct {
	URLs  []string
	Count int
}

func buildCrawlHeaders(options Options) []string {
	headers := []string{}
	headers = append(headers, "User-Agent: "+randomUserAgent())
	acceptLangs := []string{"en-US,en;q=0.9", "en-GB,en;q=0.8,en-US;q=0.7", "en-US,en;q=0.9,fr;q=0.8"}
	headers = append(headers, "Accept-Language: "+acceptLangs[rand.Intn(len(acceptLangs))])
	headers = append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	headers = append(headers, "Accept-Encoding: gzip, deflate, br")
	headers = append(headers, "Sec-Ch-Ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"131\", \"Google Chrome\";v=\"131\"")
	headers = append(headers, "Sec-Ch-Ua-Mobile: ?0")
	headers = append(headers, "Sec-Ch-Ua-Platform: \"Windows\"")
	headers = append(headers, "Sec-Fetch-Dest: document")
	headers = append(headers, "Sec-Fetch-Mode: navigate")
	headers = append(headers, "Sec-Fetch-Site: none")
	headers = append(headers, "Sec-Fetch-User: ?1")
	headers = append(headers, "Upgrade-Insecure-Requests: 1")
	headers = append(headers, "Cache-Control: max-age=0")

	if cookie := strings.TrimSpace(options.Cookie); cookie != "" {
		headers = append(headers, "Cookie: "+cookie)
	}

	for _, header := range normalizeList(options.Headers) {
		if !strings.HasPrefix(strings.ToLower(header), "user-agent:") &&
			!strings.HasPrefix(strings.ToLower(header), "cookie:") {
			headers = append(headers, header)
		}
	}

	return headers
}

func CrawlTarget(ctx context.Context, target string, concurrency int, maxDepth int, logWriter io.Writer, options ...Options) (CrawlResult, error) {
	if logWriter == nil {
		logWriter = io.Discard
	}

	var opts Options
	if len(options) > 0 {
		opts = options[0]
	}

	crawlConcurrency := defaultInt(int(float64(concurrency)*0.2), 30)
	if crawlConcurrency < 5 {
		crawlConcurrency = 5
	}
	if crawlConcurrency > 100 {
		crawlConcurrency = 100
	}

	if maxDepth <= 0 {
		maxDepth = 2
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return CrawlResult{}, fmt.Errorf("invalid target URL for crawl: %w", err)
	}
	domainScope := parsedURL.Hostname()

	result, headlessErr := executeCrawl(ctx, target, domainScope, crawlConcurrency, maxDepth, true, logWriter, opts)
	if headlessErr == nil && result.Count > 0 {
		return result, nil
	}

	if headlessErr != nil && opts.Verbose {
		fmt.Fprintf(logWriter, "\n[WARN] headless crawl failed (%v), falling back to standard HTTP\n", headlessErr)
	}

	result, stdErr := executeCrawl(ctx, target, domainScope, crawlConcurrency, maxDepth, false, logWriter, opts)
	if stdErr != nil {
		return CrawlResult{}, stdErr
	}

	return result, nil
}

func executeCrawl(ctx context.Context, target string, domainScope string, crawlConcurrency int, maxDepth int, useHeadless bool, logWriter io.Writer, opts Options) (CrawlResult, error) {
	var mu sync.Mutex
	var crawledURLs []string
	var urlCount int64

	done := make(chan struct{})
	go func() {
		defer close(done)
		elapsed := 0
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				elapsed += 3
				count := atomic.LoadInt64(&urlCount)
				fmt.Fprintf(logWriter, "\r%s active=%s target=%s found=%s", "[CRAWL]", fmt.Sprintf("%ds", elapsed), target, fmt.Sprintf("%d URLs", count))
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	katanaHeaders := buildCrawlHeaders(opts)

	katanaOptions := &types.Options{
		MaxDepth:          maxDepth,
		FieldScope:        "rdn",
		Proxy:             opts.Proxy,
		BodyReadSize:      math.MaxInt,
		Timeout:           20,
		Concurrency:       crawlConcurrency,
		Parallelism:       crawlConcurrency / 2,
		Delay:             0,
		RateLimit:         15,
		Strategy:          "depth-first",
		CustomHeaders:     katanaHeaders,
		Headless:          useHeadless,
		HeadlessNoSandbox: useHeadless,
		TlsImpersonate:    true,
		ScrapeJSResponses: true,
		OnResult: func(result output.Result) {
			if ctx.Err() != nil {
				return
			}
			reqURL := result.Request.URL
			if reqURL == "" {
				return
			}
			parsed, parseErr := url.Parse(reqURL)
			if parseErr != nil {
				return
			}
			reqDomain := parsed.Hostname()
			if !strings.HasSuffix(reqDomain, domainScope) && reqDomain != domainScope {
				return
			}
			mu.Lock()
			crawledURLs = append(crawledURLs, reqURL)
			mu.Unlock()
			atomic.AddInt64(&urlCount, 1)

			if result.Response.Body != "" {
				action := extractFormAction(result.Response.Body)
				if action != "" {
					formURL, parseErr := url.Parse(action)
					if parseErr == nil {
						if !formURL.IsAbs() {
							base, _ := url.Parse(reqURL)
							if base != nil {
								formURL = base.ResolveReference(formURL)
							}
						}
						fullURL := formURL.String()
						if fullURL != reqURL {
							mu.Lock()
							crawledURLs = append(crawledURLs, fullURL)
							mu.Unlock()
							atomic.AddInt64(&urlCount, 1)
							fmt.Fprintf(logWriter, "\r%s form_action=%s\n", "[CRAWL]", fullURL)
						}
					}
				}
			}
		},
	}

	crawlerOptions, err := types.NewCrawlerOptions(katanaOptions)
	if err != nil {
		<-done
		return CrawlResult{}, fmt.Errorf("failed to initialize crawler options: %w", err)
	}

	var crawler *standard.Crawler
	crawler, err = standard.New(crawlerOptions)
	if err != nil {
		crawlerOptions.Close()
		<-done
		return CrawlResult{}, fmt.Errorf("failed to initialize crawler engine: %w", err)
	}
	defer crawler.Close()

	defer crawlerOptions.Close()

	crawlErr := crawler.Crawl(target)
	<-done

	if crawlErr != nil {
		return CrawlResult{}, fmt.Errorf("crawl failed for %s: %w", target, crawlErr)
	}

	fmt.Fprintf(logWriter, "\r%s active=%s target=%s found=%s\n", "[CRAWL]", "done", target, fmt.Sprintf("%d URLs", len(crawledURLs)))

	return CrawlResult{
		URLs:  crawledURLs,
		Count: len(crawledURLs),
	}, nil
}

func WriteTargetsToFile(urls []string) (string, func(), error) {
	tmpFile, err := os.CreateTemp("", "serahkan-crawl-*.txt")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp targets file: %w", err)
	}
	cleanup := func() {
		os.Remove(tmpFile.Name())
	}

	for _, u := range urls {
		if _, err := tmpFile.WriteString(u + "\n"); err != nil {
			tmpFile.Close()
			cleanup()
			return "", nil, fmt.Errorf("failed to write target to file: %w", err)
		}
	}
	tmpFile.Close()

	return tmpFile.Name(), cleanup, nil
}
