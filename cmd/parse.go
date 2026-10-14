package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	unifiedlogs "github.com/Velocidex/go-macos-unifiedlogs"
	"github.com/Velocidex/go-macos-unifiedlogs/filtering"
	kingpin "github.com/alecthomas/kingpin/v2"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/types"
)

var (
	parse_command = app.Command(
		"parse", "Parse files.")

	parse_command_file_arg = parse_command.Arg(
		"directory", "The logarchive directory",
	).Required().String()

	parse_command_filter = parse_command.Flag(
		"filter", "A VQL Filter to eliminate rows").String()

	parse_command_format = parse_command.Flag("format",
		"Output format (jsonl, json)").Default("jsonl").String()
)

func doParse() (err error) {
	count := &Counter{}

	if *verbose_flag {
		defer func() {
			fmt.Fprintf(os.Stderr, "Parsed %v events. Stats %#v",
				count.Get(), unifiedlogs.GetStats())
		}()
	}

	var printer func(l interface{})
	switch *parse_command_format {
	case "", "jsonl":
		printer = jsonlRowPrinter
	case "json":
		printer = jsonRowPrinter
	default:
		return fmt.Errorf("Unsupported output format %v", *parse_command_format)
	}

	ctx, cancel := Install_sig_handler()
	defer cancel()

	var (
		scope      vfilter.Scope
		vql_filter *vfilter.VQL
	)

	if *parse_command_filter != "" {
		vql_filter, err = vfilter.Parse("SELECT * FROM plugin() WHERE " + *parse_command_filter)
		if err != nil {
			return err
		}

		scope = filtering.NewScope()
	}

	provider := unifiedlogs.NewLogarchiveProvider(
		*parse_command_file_arg)
	if err != nil {
		return err
	}

	if *verbose_flag {
		provider.SetLogger(log.New(os.Stderr, "", 0))
	}
	unifiedlogs.ResetStats()

	parser := unifiedlogs.NewUnifiedLogParser(
		provider, provider.Logger(),
		unifiedlogs.NewMemoryStringCache(),
		unifiedlogs.ParserOptions{
			Threads: 5,
		},
	)

	events, err := parser.Parse(ctx)
	if err != nil {
		return err
	}

	for l := range events {
		// Evaluate the filter on the row and only allow
		// it when it matches.
		if scope != nil &&
			!filterLog(ctx, scope, vql_filter, &l) {
			continue
		}

		select {
		case <-ctx.Done():
			return

		default:
			printer(filtering.WrapLogData(&l))
			count.Inc()
		}
	}

	return nil
}

func jsonlRowPrinter(log interface{}) {
	serialized, err := json.Marshal(log)
	if err == nil {
		fmt.Printf("%v\n", string(serialized))
	}
}

func jsonRowPrinter(log interface{}) {
	serialized, err := json.MarshalIndent(log, " ", " ")
	if err == nil {
		fmt.Printf("%v\n", string(serialized))
	}
}

func filterLog(
	ctx context.Context, scope types.Scope,
	vql_filter *vfilter.VQL,
	log *unifiedlogs.LogData) bool {
	sub_scope := scope.Copy().AppendVars(log)
	defer sub_scope.Close()

	res := vql_filter.Query.Where.Reduce(ctx, sub_scope)
	return scope.Bool(res)
}

func FatalIfError(command *kingpin.CmdClause, cb func() error) {
	err := cb()
	kingpin.FatalIfError(err, "%s", command.FullCommand())
}

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case parse_command.FullCommand():
			FatalIfError(parse_command, doParse)
		default:
			return false
		}
		return true
	})
}

type Counter struct {
	mu    sync.Mutex
	value int
}

func (self *Counter) Inc() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.value++
}

func (self *Counter) Get() int {
	self.mu.Lock()
	defer self.mu.Unlock()

	return self.value
}
