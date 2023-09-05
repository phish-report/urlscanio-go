package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"phish.report/urlscanio-go"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	if len(os.Args) < 2 {
		fmt.Println("expected 'scan' or 'search' subcommand")
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "scan":
		err = scan(ctx)
	case "search":
		err = search(ctx)
	default:
		err = fmt.Errorf("unknown command %s", os.Args[1])
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var searchFlags = flag.NewFlagSet("search", flag.ExitOnError)

func search(ctx context.Context) error {
	size := searchFlags.Int("size", 100, "Number of results to return")
	if err := searchFlags.Parse(os.Args[2:]); err != nil {
		return err
	}
	query := searchFlags.Arg(0)
	resp, err := urlscanio.NewClient(urlscanio.APIKey(os.Getenv("URLSCAN_API_KEY"))).Search(ctx, urlscanio.SearchRequest{Query: query, Size: *size})
	if err != nil {
		return err
	}
	fmt.Println(resp.Total, "results")
	for _, r := range resp.Results {
		fmt.Println(r.Task.Url)
	}
	return nil
}

var scanFlags = flag.NewFlagSet("scan", flag.ExitOnError)

func scan(ctx context.Context) error {
	visibility := scanFlags.String("visibility", "public", "Visibility of the scan. Valid values are: public, unlisted, private")
	country := scanFlags.String("country", "", "Country code to scan this URL from.")
	if err := scanFlags.Parse(os.Args[2:]); err != nil {
		return err
	}

	client := urlscanio.NewClient(urlscanio.APIKey(os.Getenv("URLSCAN_API_KEY")))
	resp, err := client.Scan(ctx, urlscanio.ScanRequest{
		URL:        scanFlags.Arg(0),
		Visibility: *visibility,
		Country:    *country,
	})
	if err != nil {
		return err
	}
	fmt.Println(resp.Message, resp.ResultURL)

	fmt.Println("Polling for result...")
	result, err := client.PollResult(ctx, resp.Uuid)
	fmt.Println(result, err)
	return err
}
